<!--
SPDX-License-Identifier: MIT
SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR
-->

# Deployment and operation

| Mode | Services and ownership |
| --- | --- |
| Standalone | Agent + local CLI; redb and administrative Unix socket |
| Development control plane | Cloud + cluster + agent + existing etcd; separate tier prefixes |
| NixOS fleet | Inventory-selected roles, generated configuration and external credentials |
| Existing NixOS host | Imported modules; operator retains hardware, mounts and firewall policy |

For the deployment tool, follow the [MeisterDeploy walkthrough](../tools/meister-deploy/docs/DEPLOYMENT.md),
[single-node guide](../tools/meister-deploy/docs/SINGLE_NODE.md), or
[multi-node guide](../tools/meister-deploy/docs/MULTI_NODE.md).
No live installation, deployment or rollback was executed for this review. See [Nix](NIX.md) and
[configuration](CONFIGURATION.md) for rendering and field meanings.

## Prerequisites

- Linux and `/dev/kvm` for VMs; runtime binaries and configured VMM/backends.
- Correct ownership/access for state, image, volume and runtime directories.
- Selected driver tools: `ip`, `qemu-img`, `curl`, and optionally nftables, LVM,
  NFS or NVMe utilities. See [drivers](DRIVERS.md).
- Controller etcd endpoints/prefixes, advertised addresses and trust material.
- Firewall access for REST/gRPC and selected migration/storage dataplane paths.
- Configuration checks validate selected prerequisites, not live operations.

## Standalone node

Leave `controller_addr` and `controller_addrs` unset. Local VMs have no cloud
objects, placement or tenant authorization.

**NixOS:** use the agent role with `meisterstack.singleNode.enable`; list local
administrators in `meisterstack.singleNode.operators`. Examples:
[inventory](../examples/fleet/single-node.toml),
[profile](../templates/operator/profiles/single-node.nix).

**Other Linux:** [installer](../scripts/meisterstack-install.sh) modes are
`single-node` and `cli`. Supply executable files from `meisterstack-static` and
`cloud-hypervisor-meister-static` together through `--bin-dir`.

| Path | Content |
| --- | --- |
| `/opt/meisterstack/bin/` | Binaries |
| `/usr/local/bin/meister` | CLI symlink |
| `/etc/meisterstack/{agent,cli}.toml` | System configuration |
| `/var/lib/meisterstack/` | Images, volumes and agent database |
| `/etc/systemd/system/meister-agent.service` | Agent unit |

- `--root DIR`: scratch installation, skipping groups/systemd; `--dry-run`: print steps.
- Existing config/units require `--force` to replace; binaries are replaced regardless.
- Missing host tools are warnings. Installation is not a transactional running-node upgrade.
- OIDC needs a writable user profile/cache. An implicit cache under a system config
  resolves beneath `/etc/meisterstack`, contrary to the installer's user-cache hint.

```sh
meister --endpoint unix:///run/meisterstack/agent/agent.sock agent vm ls
meister --endpoint unix:///run/meisterstack/agent/agent.sock agent vm create -f spec.json
meister --endpoint unix:///run/meisterstack/agent/agent.sock agent vm observe <id>
```

Use a bare [NewVmSpec example](../config/json/README.md), replacing host resources.

## Control plane and fleet

1. Build the runtime packages in the [root README](../README.md).
2. Select [development or hardened config](../config/README.md); restrict development
   bearer/plain-HTTP access to the intended local network.
3. Start cloud and cluster with distinct etcd prefixes, then connect agents.
4. Inspect discovery, node conditions, capabilities, pools and images before workloads.

For NixOS, start from [templates/operator](../templates/operator/):

- Pin inputs; define hosts, groups, roles and addresses in `fleet.toml`.
- Separate common profiles from hardware modules; avoid duplicate mount definitions.
- Keep private keys outside Git and the Nix store; verify SSH host keys separately.
- Evaluate configurations and inspect the manifest before building.
- Workflow: `resolve → build → plan → apply`. Enrollment, installation and workload
  checks are separate. See the [command map](../tools/meister-deploy/docs/COMMANDS.md)
  and [recovery contracts](../tools/meister-deploy/docs/EXECUTION.md).
- Standalone upgrades currently require ordinary NixOS activation: MeisterDeploy
  incorrectly requires controller maintenance for changed standalone agents.

| Boot/host mode | Configuration |
| --- | --- |
| UEFI install | ESP + systemd-boot |
| Direct boot | Provider supplies kernel, initrd and command line |
| Existing grub host | Own bootloader; no installation path |
| Existing NixOS flake | Import `nixosModules.services` or `hostModules.<id>` with host hardware policy |

See the [foreign-flake example](../examples/fleet/foreign-flake/flake.nix).
The local observability profile remains a placeholder with a pre-existing Nix
syntax error. A successful build alone does not validate reboot or rollback.

## Privileges, upgrade and recovery

- Agent normally runs as root. Optional unprivileged mode restricts available drivers.
- `vmm_user` separately changes supported VMM/backend credentials; check device and
  parent-directory access. virtiofsd has its own privileged sandbox path.
- Local agent/VMM sockets remain administrative. See [security](SECURITY.md).
- Preserve redb, etcd namespaces, backend handles and operation receipts across restart.
- Settle active migrations before protocol changes; coordinate participating agent and
  controller versions. Additive decoding does not establish semantic compatibility.
- Inspect actual processes and ownership after restart. Health does not prove completion.
- Unknown migration/cleanup outcomes retain evidence and ownership; current receive
  defects are listed in [migration](MIGRATION.md).
- CRL enforcement is opt-in; monitor reload failures. Credential rotation and system
  rollback are separate operations.

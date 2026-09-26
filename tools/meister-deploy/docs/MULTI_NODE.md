# Multi-node fleet

Use separate service identities for cloud, cluster and compute roles. Begin with
[workstation/repository setup](DEPLOYMENT.md), then define the topology below before
resolving. These are source-based configuration examples, not a tested live fleet.

## Small controller fleet

A practical starting layout has three single-role hosts:

| Host | Role | Group | Purpose |
| --- | --- | --- | --- |
| `cloud-1` | `cloud` | `cloud` (raft singleton) | User API and cluster placement |
| `cluster-1` | `cluster` | `cp` (raft singleton) | Node placement and agent sessions |
| `a1` | `agent` | `compute` | Workloads; `controller_group = "cp"` |

Singletons have no replica availability during interruption. Their deployment
plans require explicit outage approval. Use real management addresses, interfaces,
DNS/SANs and separate hardware modules. Replace the template's mixed-role `cp-1`;
keep the common `[fleet]`, `[defaults]` and `[operator]` tables from setup.

```toml
[[group]]
id = "cloud"
kind = "raft"
profiles = ["controller"]

[[group]]
id = "cp"
kind = "raft"
profiles = ["controller"]

[[group]]
id = "compute"
kind = "compute"
profiles = ["compute-cpu"]
rollout = { canary = "compute-cpu" }

[[host]]
id = "cloud-1"
name = "cloud-1"
deployment = "nixos"
roles = ["cloud"]
groups = ["cloud"]
networks.management = { address = "10.0.0.10", prefix = 24, interface = "eno1" }
modules = ["hosts/cloud-1.nix"]

[[host]]
id = "cluster-1"
name = "cluster-1"
deployment = "nixos"
roles = ["cluster"]
groups = ["cp"]
networks.management = { address = "10.0.0.11", prefix = 24, interface = "eno1" }
modules = ["hosts/cluster-1.nix"]

[[host]]
id = "a1"
name = "a1"
deployment = "nixos"
roles = ["agent"]
groups = ["compute"]
controller_group = "cp"
networks.management = { address = "10.0.0.20", prefix = 24, interface = "eno1" }
capabilities = ["kvm"]
modules = ["hosts/a1.nix"]
```

Management addresses describe endpoints unless `static = true` requests interface
configuration. Preserve working SSH access when changing networking. Add verified
`ssh.host_key` values after enrollment; add install tables only for hosts that need
installation. An existing machine retains its real mounts and bootloader.

Nix derives agent controller endpoints from `controller_group`; cluster controllers
receive the fleet's cloud endpoints. Logical tier names come from rendered group
identity. Review the resolved configuration before issuing certificates rather
than assuming each service identity equals its operating-system hostname.

## Bootstrap sequence

1. Resolve/build the complete intended fleet. Install or adopt each host, then
   enroll its independently verified SSH key.
2. Commit fingerprints and rebuild the resolved release. Generate target identity
   keys/CSRs; issue `cloud`, `cluster`, and `node` certificates for the respective hosts.
   Controllers also need serving certificates with the actual client addresses.
3. Check all secret references, including CA trust and the cloud encryption key.
   Configure the workstation's administrative `meister` profile.
4. Plan `bootstrap` with `--select all`; review dependencies, blockers and each
   approval. Apply only a complete plan for the intended hosts.
5. Check service readiness and authenticated communication, then create a test
   workload and verify cleanup. An active unit/socket alone is insufficient.

The [common walkthrough](DEPLOYMENT.md#5-enroll-ssh-and-service-credentials) gives
commands. If bootstrapping in smaller stages, select cloud hosts first, then cluster
hosts, then agents. Re-observe and replan between stages; a subset does not prove
excluded hosts are ready.

Configure a user CLI profile as in the [CLI guide](../../../docs/CLI.md), then:

```sh
meister --profile cloud whoami
meister --profile cloud api-resources
meister --profile cloud cluster ls
meister --profile cloud node ls --cluster cp
```

Use the cluster name actually rendered/registered by this fleet. Before creating
VMs, establish an authorized tenant, available images, storage pools, networking
and sufficient node capacity. The deployment tool does not create a ready-to-use
tenant workload environment merely by starting the services.

## Three-member groups

For replica availability, use three single-role cloud hosts in their raft group
and three single-role cluster hosts in theirs, spread across real failure domains.
One or more agents join the compute group. Each machine has its own host ID,
management address, serving key and hardware module; replicas share the logical
tier identity name, not a private key file copied between machines.

- Supported raft group sizes are 1, 3 and 5. Two members do not form a supported
  intermediate deployment topology.
- Keep peer addresses reachable and preserve etcd data paths across upgrades.
- Inspect actual etcd membership and health before disruption. Planning limits
  waves to one member per raft group and accounts for unavailable members.
- Adding/removing peers is a membership operation, not a normal package upgrade.
  Do not change the inventory and assume apply performs a safe membership migration.
- The unavailable-member repair exemption currently can bypass topology blockers.
  Independently verify membership when repairing or changing a group.

The [HA fixture](../../../examples/fleet/ha.toml) illustrates groups, failure domains
and persistence, but includes a mixed cloud/cluster host. Adapt it to separate
roles before using the default authenticated configuration.

## One physical machine

A standalone agent is the [single-node mode](SINGLE_NODE.md). A full cloud/cluster/
agent stack on one physical machine still has three roles and control-plane state.
Separate NixOS VMs with one role each can use the workflow above, subject to the
host/provider's networking and virtualization support. Creating those VMs is an
external provisioning step.

**Current combined-role limit:** the default generated services share
`identity.key` and `identity.crt`. `keys csr --as cloud|cluster|node` chooses one
subject; it does not create independent identities for all co-located tiers.
The [one-box fixture](../../../examples/fleet/one-box.toml) therefore establishes
configuration structure, not a complete authenticated deployment recipe. Per-role
PKI overrides need separate implementation/validation; disabling authentication
is not part of this guide.

## Upgrades and acceptance

Follow [upgrade/recovery](DEPLOYMENT.md#7-upgrade-and-recover). Keep old release and
run evidence until the new generation has passed the required checks. Exercise the
actual user path: authentication → discovery → create → observed Running state →
console/output → delete → verified absence. Add storage, GPU or RDMA checks only
where the fleet declares and provides those capabilities.

`verify` has [coverage and cleanup limits](HOST_OPERATIONS.md#functional-verification).
Record actual placement, hardware and test outcomes when using these runs as
thesis evidence. A source-derived guide is not an experiment result.

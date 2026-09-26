# Single node

A standalone node runs one agent and the local CLI. It has no cloud controller,
cluster controller, tenant directory or scheduler. Local socket access grants full
agent administration. A complete control plane on one physical machine is a
different topology; see [multi-node](MULTI_NODE.md#one-physical-machine).

## Host configuration

Follow [workstation and repository setup](DEPLOYMENT.md#1-prepare-the-workstation).
Ensure `profiles/single-node.nix` exists: the current `init` binary omits it. Replace
the template's example hosts/groups with one agent; for example:

```toml
schema = 2

[fleet]
name = "desk"

[operator]
signing_key = "keys/signing.sec"

[defaults]
ssh = { user = "root", port = 22 }
profiles = ["base", "single-node"]
rollout = { max_unavailable = 1, reboot = "approve" }
checks = { required = ["units", "session"] }

[[host]]
id = "rig"
name = "rig"
deployment = "nixos"
roles = ["agent"]
networks.management = { address = "10.0.0.20", prefix = 24, interface = "eno1" }
capabilities = ["kvm"]
modules = ["hosts/rig.nix"]
```

No `controller_group`, controller role or raft membership is needed. The profile
sets `meisterstack.singleNode.enable = true` and disables FRR/NVMe-TCP. Adapt
`hosts/rig.nix` to the real hardware, filesystems, bootloader and SSH access.
Add the intended existing local account in that host module:

```nix
{ ... }: {
  meisterstack.singleNode.operators = [ "alice" ];
}
```

This grants membership in `meister`; it does not create a complete login account
or its authentication policy. Configure image, volume, network and VMM paths as
needed. Declaring `kvm` is not proof that virtualization is available.

## First installation

For a blank disk, add the actual `install` layout and disk identity, then follow
[resolve/build](DEPLOYMENT.md#3-resolve-and-build) and
[target installation](DEPLOYMENT.md#fresh-disk-installation), replacing `a1` with
`rig`. The installation medium installs the desired system directly. After boot,
enroll the trusted SSH fingerprint and commit it to the inventory as described in
[enrollment](DEPLOYMENT.md#5-enroll-ssh-and-service-credentials).

A default standalone node uses its local socket and has no controller identity
credential references. Do not create a CA or issue controller certificates solely
for this mode. Additional explicitly configured services may have their own needs.

For an existing NixOS host, import `nixosModules.services` and enable the agent role
and `meisterstack.singleNode.enable`, or use the generated host module. Another
option is to activate the reviewed fleet output **on the target**.

Clone/copy the committed operator repository and locked inputs' references to
`/srv/fleet` on that target first, including `signing.pub`; keep workstation private
keys outside that copy. Then run:

```sh
sudo nixos-rebuild switch --flake /srv/fleet#rig
```

Review the hardware/mount definitions and preserve the existing `stateVersion`
before activation. This uses the ordinary NixOS workflow, without a MeisterDeploy
plan or receipt. Reboot separately when the changed kernel/boot configuration
requires it. Non-NixOS installation uses the
[runtime installer](../../../docs/DEPLOYMENT.md#standalone-node).

## First local session

The module writes `/etc/meisterstack/cli.toml` with profile `local` and the effective
agent socket path. An existing per-user config takes precedence; select the system
config explicitly when testing:

```sh
systemctl status meister-agent
meister --config /etc/meisterstack/cli.toml --profile local agent vm ls
```

Log in again after changing group membership. Prepare a bare VM specification
whose boot/image/network resources exist on this host, then:

```sh
meister --config /etc/meisterstack/cli.toml --profile local agent vm create -f my-vm.json
meister --config /etc/meisterstack/cli.toml --profile local agent vm observe VM_ID
```

Use the returned ID. See [CLI examples](../../../docs/CLI.md#local-agent) for the
specification format and lifecycle. The default agent build enables local mutation
routes; custom builds need `debug-mutations`. Local volumes use inline disk specs;
`agent volume` only lists and reads.

## Changes and recovery

**Current MeisterDeploy limitation:** changed standalone agents are treated as
controller-managed agents by maintenance planning. `bootstrap` and `upgrade` can
block even with zero running guests; a local CLI profile does not supply the
required `controller_group`. Do not fabricate enrollment or observation values to
bypass this check. Initial install and unchanged observations/plans are separate.

Use the existing NixOS activation workflow for subsequent standalone changes:

1. Inspect local VMs and settle active operations. Stop guests that cannot tolerate
   the planned service, device, network or kernel change.
2. Commit and evaluate the intended configuration; activate it on the target.
3. Inspect services, current/booted generation, local VM state and host resources.
4. Start or recover guests only after their resource ownership is understood.

NixOS generation rollback does not restore guest disks or the agent database.
Retain agent state and backend handles across restarts; inspect
[resource recovery](../../../docs/RESOURCE_LIFECYCLE.md) before manual cleanup.

Sources: [single-node module](../../../nix/single-node.nix),
[profile](../../../templates/operator/profiles/single-node.nix),
[inventory example](../../../examples/fleet/single-node.toml),
[planner limitation](MODEL.md#plan-contents-and-decisions).

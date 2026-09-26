# Deployment walkthrough

Use this workflow for managed NixOS hosts. Start with [single node](SINGLE_NODE.md)
or [multi-node](MULTI_NODE.md) to choose the topology. Existing non-NixOS runtime
installation is covered by [MeisterStack deployment](../../../docs/DEPLOYMENT.md).

Commands below run on the operator workstation unless marked **on the target**.
Replace sample paths, addresses, identities and IDs before use. These examples
were checked against source and CLI syntax; they are not a hardware test record.

## 1. Prepare the workstation

Required: Git, Nix with flakes enabled, OpenSSH, the three deployment binaries,
`meister`, OpenSSL and `meister-ca`. `jq` is used below for inspection. Nix needs
access to the locked inputs and selected builders/caches. Targets need NixOS,
root-capable SSH access, and the declared hardware, filesystems and networking.

From the MeisterStack checkout:

```sh
nix build .#meisterstack
nix build .#meister-ca --out-link result-ca
```

Put `result/bin` and `result-ca/bin` on PATH, or use their absolute paths. Cargo
builds the Rust binaries but does not provide external tools. Use one tool revision
for workstation, target helper and installer until compatibility is checked.

## 2. Create the operator repository

Keep fleet configuration separate from the MeisterStack source checkout:

```sh
meister-deploy init /srv/fleet
cd /srv/fleet
git init
```

`init` writes templates and attempts `nix flake lock`. Check the exit diagnostics
and require a valid `flake.lock`; a failed lock attempt does not make `init` fail.
Pin `inputs.meisterstack.url` to the intended revision before final locking.

**Current template defect:** the binary omits `profiles/single-node.nix`, although
`profiles.nix` references it. Copy that file from
[`templates/operator/profiles/single-node.nix`](../../../templates/operator/profiles/single-node.nix)
at the same revision, or initialize from the complete `#operator` Nix flake template.
Do not assume a successful `init` proves the selected profiles can evaluate.

Configure:

| File | What to set |
| --- | --- |
| `fleet.toml` | Stable host IDs, roles/groups, management addresses, SSH fingerprints, rollout policy |
| `profiles.nix`, `profiles/*.nix` | Shared service and site policy |
| `hosts/<id>.nix` | Hardware, boot, existing mounts or installation device, SSH access |
| `flake.nix`, `flake.lock` | Pinned inputs and fleet outputs |
| `known_hosts` | Public SSH keys enrolled through trusted fingerprints |
| `signing.pub` | Public Nix closure-signing key trusted by the hosts |

Retain an existing host's `system.stateVersion`. For adoption, describe its actual
mounts and bootloader; do not reuse example filesystem labels blindly. For fresh
installation, let the chosen disko layout own those mounts. Configure authorized
SSH keys explicitly and test console access before changing networking. In the
installed host module, for example:

```nix
{ ... }: {
  users.users.root.openssh.authorizedKeys.keys = [ "ssh-ed25519 REPLACE_WITH_YOUR_PUBLIC_KEY" ];
}
```

`install.authorized_keys` grants access to installation media only; it does not
authorize SSH login to the installed system.

Generate a Nix signing key for this fleet; the template ignores `keys/`:

```sh
mkdir -p keys .meister-deploy/artifacts
nix-store --generate-binary-cache-key my-fleet keys/signing.sec signing.pub
```

The base profile trusts `signing.pub`. Add an operator table **before any
`[[host]]` or `[[group]]` entries**:

```toml
[operator]
signing_key = "keys/signing.sec"
ca_dir = "../fleet-pki"
# For controller-managed agents, use a working administrative CLI profile:
cli_config = "/srv/fleet-operator/cli.toml"
cli_profile = "cloud"
```

Keep the CA directory outside the repository and Nix store. Keep local CLI
credentials outside tracked files. The example absolute CLI path must exist on
this workstation; it is used for cordon/drain and workload verification.

```sh
meister-deploy inventory -f /srv/fleet/fleet.toml
meister-deploy validate -f /srv/fleet/fleet.toml
git add flake.nix fleet.toml profiles.nix profiles hosts disko tests .gitignore signing.pub known_hosts
nix flake lock
git add flake.lock
git commit -m 'Configure fleet topology and host policy'
```

Inspect the staged files before committing. Ordinary resolution requires a clean
source tree. Stage the new configuration before locking so Git-backed flake
evaluation includes it. Store generated manifests/plans under ignored `.meister-deploy/`;
root-level JSON output files are not ignored by the template. `--dev` captures a
dirty snapshot and is unsuitable as a substitute for reviewed deployment source.

## 3. Resolve and build

Run these commands from `/srv/fleet`:

```sh
meister-deploy resolve --repo /srv/fleet --out .meister-deploy/artifacts/manifest.json
meister-deploy build --manifest .meister-deploy/artifacts/manifest.json \
  --repo /srv/fleet --inventory /srv/fleet/fleet.toml \
  --out .meister-deploy/artifacts/release.json
```

Resolve evaluates the pinned configuration. Build realizes, signs and measures
its artifacts and runs required build checks. Inspect host coverage, boot mode,
secret references and required checks in the output. A successful build does not
establish that a target boots, authenticates or runs workloads.

Use absolute `--inventory` when passing `--repo`, especially with artifacts moved
between workstations: current handlers resolve relative overrides inconsistently.
`build --verify-reproducible` requests an additional build comparison; without it,
the release makes no measured bit-identical-build claim.

## 4. Install a new host, or adopt an existing one

### Fresh disk installation

The host inventory needs an `install` table: stable disk serial/size, layout path,
preservation policy and optional public installer SSH keys. Bind the layout to
the real `/dev/disk/by-id/…` path in the hardware module. Review the selected disk
and independent backups before proceeding.

```sh
meister-deploy plan --release .meister-deploy/artifacts/release.json \
  --kind install --select host=a1 --repo /srv/fleet \
  --inventory /srv/fleet/fleet.toml --out .meister-deploy/artifacts/install-plan.json
jq '{plan_id, approvals, actions}' .meister-deploy/artifacts/install-plan.json
```

An un-enrolled, unreachable first-install host is permitted; this does not prove
its disk is empty. Read the complete plan and blockers. Replace `PLAN_ID` below
with the inspected ID:

```sh
meister-deploy install --plan .meister-deploy/artifacts/install-plan.json \
  --release .meister-deploy/artifacts/release.json --host a1 \
  --repo /srv/fleet --approve destructive=PLAN_ID \
  --out .meister-deploy/artifacts/media
```

This builds media and an instruction sheet. Transfer/boot the ISO using the
machine's normal console or media workflow. **On the target, the following command
formats the selected disk**; type the host and actual serial from the sheet:

```sh
meister-install confirm --host a1 --disk ACTUAL_DISK_SERIAL --plan PLAN_ID
```

The helper checks identities, size, layout and existing installation marks, then
formats, installs and prints the new SSH fingerprint. It does not reboot. Remove
installation media and boot the installed system. Direct-boot providers must load
the release's kernel/initrd/command line. Existing GRUB hosts can be adopted, but
this installer does not create GRUB installations.

A target-side `--dry-run` still probes partitions through read-only mounts; it is
not a promise of zero host effects. Reinstall requires separate explicit policy
and confirmation. Interrupted formatting has no transactional rollback.

### Existing NixOS host

Verify its hardware/mount/boot configuration and import the fleet modules through
its existing NixOS configuration, or perform the initial local activation using
the reviewed fleet output. The host needs SSH access and a compatible
`meister-activate` for target-generated CSRs. Preserve existing host/data identity;
do not route adoption through the destructive installer merely to obtain helpers.
See the [foreign-flake example](../../../examples/fleet/foreign-flake/flake.nix).

## 5. Enroll SSH and service credentials

Obtain the host's ED25519 fingerprint through its trusted console/BMC or installer
output. Do not use keyscan output itself as the trust source.

```sh
meister-deploy keys enroll a1 --repo /srv/fleet --fingerprint 'SHA256:TRUSTED_VALUE'
```

Enrollment writes `known_hosts`; it does **not** edit the inventory. Add the same
fingerprint to that host's `ssh.host_key`, commit both files, then resolve/build
again so the release contains the enrolled identity.

For controller fleets, create the CA outside the repository:

```sh
meister-ca --dir /srv/fleet-pki --admin fleet-admin
```

Secure the CA private key. Use the generated admin credential to configure the
operator CLI; its endpoint's serving certificate must include the actual address.
Generate host keys on the target and sign only the returned CSRs. For agent `a1`:

```sh
meister-deploy keys csr --host a1 --kind identity \
  --manifest .meister-deploy/artifacts/manifest.json --repo /srv/fleet
meister-deploy keys issue --host a1 --kind node \
  --manifest .meister-deploy/artifacts/manifest.json --repo /srv/fleet \
  --inventory /srv/fleet/fleet.toml
```

Repeat identity issuance with `--kind cloud` or `cluster` for the respective
single-role hosts. Controllers also need `keys csr --kind serving` followed by
`keys issue --kind serving`; add the actual access aliases through `--san` when
needed. Signing writes local public certificates; delivery is a separate plan.
Inspect every rendered secret reference, including any cloud encryption key or
configured CRL. Resolve missing-file blockers before applying; do not invent
placeholder credentials. See [PKI](EXECUTION.md#pki-and-rotation).

For API Secret support, configure `meisterstack.cloud.settings.secrets_key` and
`meisterstack.cluster.settings.secrets_key` on their respective hosts, for example
as `/var/lib/meisterstack/pki/secrets.key`. Before resolution, create **one** shared
key for a new fleet, outside Git, and retain a protected backup:

```sh
(umask 077; set -C; openssl rand -hex 32 > /srv/fleet-pki/secrets.key)
```

The no-clobber guard refuses an existing file. Never replace an existing fleet's
key as a deployment step: it protects already stored ciphertext. Both tiers need
the same bytes. The generated secret references deliver this operator file; CSR
issuance does not create it. If adding these settings now, commit and resolve/build
again. Without the setting, Secret-backed workloads are unavailable.

## 6. Plan, inspect and apply

```sh
meister-deploy plan --release .meister-deploy/artifacts/release.json \
  --kind bootstrap --select all --repo /srv/fleet \
  --inventory /srv/fleet/fleet.toml --out .meister-deploy/artifacts/plan.json
jq '{plan_id, approvals, actions}' .meister-deploy/artifacts/plan.json
```

Review selected hosts, unknowns/blockers, waves, disruptive actions and all required
approval classes. `plan` normally probes hosts. A blocked plan is not made safe by
supplying more approvals; correct its missing prerequisites and replan.

```sh
meister-deploy apply --plan .meister-deploy/artifacts/plan.json \
  --release .meister-deploy/artifacts/release.json --repo /srv/fleet \
  --inventory /srv/fleet/fleet.toml
```

Append one `--approve CLASS=PLAN_ID` for **each** approval in the reviewed plan,
for example `--approve singleton=PLAN_ID` when it explicitly requests singleton
outage approval. Do not generate approvals blindly from JSON. Record the run ID.

```sh
meister-deploy check --release .meister-deploy/artifacts/release.json --repo /srv/fleet
meister-deploy report --run RUN_ID --repo /srv/fleet
```

Check required results and the receipt's outcome. `status` and deployment `report`
can return 0 while displaying failures. Readiness proves the implemented checks,
not an end-to-end authenticated controller session or successful guest execution.
Perform the [CLI first-connection checks](../../../docs/CLI.md#first-connection)
and a workload appropriate to the fleet.

## 7. Upgrade and recover

For upgrades, commit changed inputs, resolve/build a new release, then use
`plan --kind upgrade`. Start with a reviewed canary selection; expand only after
its observations and workload checks are satisfactory. Inspect **all** reboot
steps: the known reboot-only planning defect can bypass `reboot = never` and the
separate reboot approval. Topology changes require independent membership work;
the unavailable-member exception can currently bypass a topology blocker.

After an interruption, preserve evidence and inspect it before resuming:

```sh
meister-deploy report --run RUN_ID --repo /srv/fleet
meister-deploy status --release .meister-deploy/artifacts/release.json --repo /srv/fleet
meister-deploy apply --resume RUN_ID --repo /srv/fleet --inventory /srv/fleet/fleet.toml
```

Resume loads saved plan/release files and reconciles observed target state.
Required approvals still apply. Older runs without both input copies need an
explicit matching `--plan` and `--release`. An expired or invalidated plan can
require a new plan; a lost reply is not proof the last side effect failed.

On the target, inspect `meister-activate status`, `txn list`, `txn show ID`, and
`lock show`. Do not delete lock/transaction files to force progress. Explicit
`--takeover OLD_RUN_ID` needs verified ownership and fresh evidence. Direct-boot
waiting states require the external provider action before resume. Certificate
rotation has a known restart-progress gap; inspect service identity after resume.
See [execution recovery](EXECUTION.md) and [target recovery](HOST_OPERATIONS.md).

## Functional checks and troubleshooting

`verify --suite vm-lifecycle|gpu|rdma --approve verify=RELEASE_ID` performs real
workload or fabric operations. Read [verification limits](HOST_OPERATIONS.md#functional-verification)
before running it: selection is not proof of per-host placement, the VM budget is
not a global ceiling, and interrupted cleanup can leave resources. `verify --json`
currently prefixes JSON with a run ID; prefer the saved `verify.json` for parsing.

| Failure | Next evidence |
| --- | --- |
| Resolve refuses source | Git status, lock file, selected Nix modules; missing template profile |
| Build cannot sign | Absolute inventory path, signing-key reference, public host trust |
| SSH/enrollment blocked | Trusted fingerprint, inventory value, repository known_hosts, address/port |
| Credential delivery blocked | Manifest secret refs, target key presence, issued public files, CA directory |
| Maintenance blocked | Operator CLI config/profile, permissions, actual cluster/node identity |
| Quorum/topology blocked | Live etcd membership and availability; membership change is separate |
| Host failed after activation | Receipt, target transactions, current/booted systems, services and data |
| Installer failed | Console output, actual disk/mount state and installation mark; no automatic rollback |

Keep full logs and state locally. [Command semantics](COMMANDS.md) describe output,
exit-code and preview exceptions. [Model](MODEL.md) documents schema/ID/version
rules; [execution](EXECUTION.md) describes saved-input compatibility and resume.

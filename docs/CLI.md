# CLI guide

`meister` manages controller resources. `meister agent …` uses a node's local Unix
API. For every command, see the [command map](CLI_COMMANDS.md); use
`meister <command> --help` for the installed binary's arguments and defaults.

## Install the CLI

From the checked-out source, with the workspace's build dependencies installed:

```sh
cargo build --locked -p meister-cli
./target/debug/meister --version
./target/debug/meister --help
```

Use `cargo build --locked --release -p meister-cli` for an optimized binary at
`target/release/meister`. The [Nix environment](NIX.md) supplies build dependencies.
The Nix `meisterstack` package includes the CLI and deployment binaries:

```sh
nix build .#meisterstack
./result/bin/meister --help
```

For a system installation on other Linux distributions, follow
[deployment](DEPLOYMENT.md#standalone-node). Installing the CLI alone starts no
services. A controller account or access to a local agent socket is required.

## First connection

Create a writable user configuration, normally
`~/.config/meisterstack/config.toml`. Replace the endpoint and use the CA and
credentials supplied by the fleet administrator:

```toml
default_profile = "cloud"

[profiles.cloud]
endpoint = "https://cloud.lab.example:3000"
ca_cert = "pki/ca.crt"
timeout_secs = 30
credential = { type = "mtls", cert = "pki/alice.crt", key = "pki/alice.key" }
```

The referenced files are relative to the configuration directory. Keep private
keys readable only by their owner. `ca_cert` is the controller's public trust
certificate; the CA private key does not belong on the client.

```sh
meister --profile cloud whoami
meister --profile cloud api-resources
meister --profile cloud -t lab vm ls
```

`whoami` establishes which identity the server sees. Discovery lists the resource
kinds and verbs that endpoint serves. A successful listing confirms API access;
it does not establish that a node can run a VM. Ask the administrator for your
tenant name; `--tenant` scopes a request and grants no additional permission.

### Configuration precedence

| Setting | Resolution |
| --- | --- |
| Config | `--config` → `MEISTER_CONFIG` → existing XDG/user config → `/etc/meisterstack/cli.toml` |
| Profile | `--profile` → `MEISTER_PROFILE` → `default_profile` |
| Endpoint | `--endpoint` → `MEISTER_ENDPOINT` → selected profile |
| Credentials | `MEISTER_TOKEN` → selected profile credential |
| Relative paths | Selected configuration directory |

An endpoint override retains the profile's credentials. Use a separate profile
for each trust boundary. Include ports explicitly. HTTPS controller profiles need
an explicit CA; OIDC provider connections can use public roots.

Credential types are `none`, `token_file`, `env`, `command`, `mtls`, and `oidc`.
`command` executes an argument vector to obtain a token. Complete examples are in
[config/examples/cli.toml](../config/examples/cli.toml).

### Login

For OIDC, use a user-owned profile with the administrator's issuer and client ID:

```toml
[profiles.cloud-oidc]
endpoint = "https://cloud.lab.example:3000"
ca_cert = "pki/ca.crt"
credential = { type = "oidc", issuer = "https://idp.lab.example/realms/lab", client_id = "meisterstack" }
```

```sh
meister --profile cloud-oidc login --oidc
meister --profile cloud-oidc whoami
```

Follow the displayed authorization instructions. Session files default to
`oidc/<profile>.json` beside the configuration; that directory must be writable.
The cloud also needs a matching User record unless provisioning is enabled.

Certificate enrollment uses `meister --profile cloud login --user alice`.
The endpoint must permit the enrollment request or accept a bootstrap credential;
a profile alone does not provide one. Login generates a key, submits a CSR, waits
for approval, then saves the issued certificate and key. An administrator can
inspect `csr ls`, `csr get NAME`, and `csr approve NAME`.

Current limits: an issuance timeout loses that invocation's unsaved key; retrying
creates a new CSR. OIDC cache lifetime can exceed token lifetime, and a 401 does
not trigger automatic retry. Existing credential files are not always tightened
on replacement. See [security](SECURITY.md).

## VM lifecycle

The following examples use an existing tenant `lab`, a configured cloud profile,
and a fleet with working compute, image, storage and networking resources.

Start from [a VM specification](../config/json/README.md). These are bare
`NewVmSpec` JSON files, not API resource envelopes:

```sh
cp config/json/plain.json my-vm.json
```

Edit `my-vm.json` before creation. Its kernel, initramfs, guest command line, base
image and network choices must match the target fleet. The fixture's Nix store
path is specific to its original guest image. Device examples additionally need
the corresponding host driver and managed device.

```sh
meister --profile cloud -t lab vm create demo -f my-vm.json --run-strategy Stopped
meister --profile cloud -t lab vm get demo -o json
meister --profile cloud -t lab vm start demo
meister --profile cloud -t lab vm ls
meister --profile cloud -t lab vm events demo
meister --profile cloud -t lab vm logs demo
meister --profile cloud -t lab vm connect demo
```

Creation and `start` acknowledge intent. Inspect placement, phase and status
message for progress; errors can arrive after the command returns. `vm connect`
opens the serial console; **Ctrl-]** detaches. There is no `vm console` command.
The guest needs a serial console configuration for useful output.

```sh
meister --profile cloud -t lab vm pause demo
meister --profile cloud -t lab vm resume demo
meister --profile cloud -t lab vm stop demo
```

Wait for the requested state before issuing dependent operations. Deletion is
separate: `meister --profile cloud -t lab vm rm demo` prompts for confirmation;
`--yes` supplies it in a script. A terminating resource remains visible while
finalizers clean up its resources.

### Placement and maintenance

```sh
meister --profile cloud cluster ls
meister --profile cloud node ls --cluster cluster-1
meister --profile cluster node ls
```

The last command assumes a separate cluster profile and suitable system/operator
credentials; an ordinary cloud User identity is not sufficient at the cluster API.

| Operation | Meaning |
| --- | --- |
| `node/cluster cordon` | Stop new placement; existing guests remain |
| `node/cluster drain` | Request evacuation subject to guest policy and locality |
| `vm reschedule NAME` | Clear placement for a stopped VM |
| `vm migrate NAME --to NODE` | Create a live-migration request; inspect its resource and events |
| `vm evacuation` | Inspect command help before permitting restart-based evacuation |

Check [migration limitations](MIGRATION.md) before using migration or drain.
Readiness alone does not settle an interrupted transfer.

## Volumes and snapshots

A storage pool must already exist and support the requested operation. Use the
same tenant for the VM and volume:

```sh
meister --profile cloud -t lab storagepool ls
meister --profile cloud -t lab volume create data --size-gib 10 --pool fast
meister --profile cloud -t lab volume get data -o json
meister --profile cloud -t lab vm attach demo --volume data
```

Wait for volume readiness before attachment. The guest must discover, format and
mount a new blank disk. Attachment does not perform guest filesystem operations.
Detach with `vm detach demo --volume data` after the guest has stopped using it.
Concurrent attachment edits can overwrite one another; serialize these changes.

```sh
meister --profile cloud -t lab volumesnapshot create data-backup --volume data
meister --profile cloud -t lab volumesnapshot get data-backup -o json
meister --profile cloud -t lab volume create restored --size-gib 10 --from-snapshot data-backup
```

Wait for the snapshot result before restoring. Snapshot creation does not freeze
the guest filesystem. Backend capabilities and locality apply; see
[storage](STORAGE.md). Persistent volumes have an independent resource lifecycle.

## Resource files

`vm create -f` accepts a bare VM specification. `apply -f` accepts complete API
objects containing `apiVersion`, `kind`, `metadata`, and `spec`. For example,
wrap the edited VM spec using `jq`:

```sh
jq '{apiVersion:"meister.io/v1", kind:"Vm", metadata:{name:"demo"},
     spec:{tenant:"lab", runStrategy:"Stopped", vm:.}}' my-vm.json > demo.json
meister --profile cloud -t lab apply -f demo.json
meister --profile cloud -t lab vm get demo -o json
```

Apply creates or replaces using the current resourceVersion. It does not provide
field-ownership merging; coordinate writers. Discovery and server schemas decide
which kinds and shapes are accepted. `-o json` is useful for reads, but `apply`
currently emits no aggregate JSON result.

### Dry-run limits

`--dry-run` adds `dryRun=All` to controller POST/PUT/PATCH. It does not consistently
cover DELETE, agent commands or login. Credential refresh can still update files.
CSR auto-approval also signs and updates User history before checking preview.
The flag is not a general no-side-effect mode.

## Local agent

For a [standalone node](../tools/meister-deploy/docs/SINGLE_NODE.md), use the local
profile installed by the NixOS module, or an explicit socket address:

```sh
meister --endpoint unix:///run/meisterstack/agent/agent.sock agent vm ls
meister --endpoint unix:///run/meisterstack/agent/agent.sock agent vm create -f my-vm.json
meister --endpoint unix:///run/meisterstack/agent/agent.sock agent vm observe VM_ID
meister --endpoint unix:///run/meisterstack/agent/agent.sock agent vm stop VM_ID
```

Replace `VM_ID` with the returned local ID. These commands bypass controller
placement and tenant authorization. Socket permissions grant administrative
access. Check the configured socket path; it can differ between installations.
Mutation routes require the agent's `debug-mutations` feature, enabled in the
current default build. `agent volume` is read-only; standalone guests use inline
disk specifications.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| No endpoint / unknown profile | Config lookup, `MEISTER_CONFIG`, `MEISTER_PROFILE`, explicit `--config` |
| Missing credential or permission error | Paths relative to config, owner-only key/token access, writable OIDC cache |
| TLS failure | Controller CA, endpoint port, certificate SAN, clock; keep trust verification enabled |
| 401 / 403 | `whoami`, profile credential, User/tenant role; renew an expired OIDC session |
| Unsupported resource | `api-resources` at that exact endpoint; cloud/cluster/local APIs differ |
| VM remains pending or fails | `vm get -o json`, events, node conditions, image paths, pool/network/device availability |
| Console fails while reads work | WebSocket proxy/upgrade path, serial configuration, [console limits](SECURITY.md#secrets-console-tickets-and-quotas) |
| Local socket refused | Agent service, configured socket path, Unix group membership; log in again after group changes |
| Delete remains terminating | Finalizers and cleanup evidence; do not infer completion from request acceptance |

Use `-v` or `-vv` for diagnostics. Preserve status and event output when reporting
an error; remove credentials and private infrastructure details before sharing.

Sources: [parser](../components/cli/src/main.rs),
[profiles](../components/cli/src/config.rs), [VM commands](../components/cli/src/vm.rs),
[resource dispatch](../components/cli/src/generic.rs),
[local commands](../components/cli/src/agent.rs).

# CLI

`meister` serves three interfaces: cloud resources, cluster resources and local
agent operations. Controller discovery determines the first two. Local operations
use `meister agent …` over a Unix socket and do not use discovery.

## Target and credentials

Configuration lookup uses `--config`, then `MEISTER_CONFIG`, an existing user
configuration under `$XDG_CONFIG_HOME/meisterstack/config.toml` (or
`~/.config/meisterstack/config.toml`), then `/etc/meisterstack/cli.toml`.
An explicit profile or `MEISTER_PROFILE` overrides `default_profile`.
An explicit endpoint or `MEISTER_ENDPOINT` overrides the profile endpoint.
Relative paths in a profile are resolved from its configuration directory.

A profile specifies `endpoint`, optional `ca_cert`, `credential` and
`timeout_secs`. Credential sources are:

| Source | Behavior |
| --- | --- |
| `none` | No client credential |
| `token_file` | Read a bearer token from a file |
| `env` | Read a named environment variable |
| `command` | Execute an argument vector and read its token output |
| `mtls` | Read the client certificate and private key |
| `oidc` | Read a cached login session and refresh an expired session when possible |

`MEISTER_TOKEN` overrides profile credentials. HTTPS controller connections require
an explicit CA file; the CLI does not use public roots for controller APIs.
OIDC provider connections can use built-in public roots or a configured private CA.
Use endpoints with explicit ports, such as `https://cloud.example:3000`.

See [configuration](CONFIGURATION.md) for examples and [security](SECURITY.md) for
server-side identity and authorization.

## Discovery and resources

```sh
meister --profile cloud api-resources
meister --profile cloud whoami
meister --profile cloud -t lab vm ls
meister --profile cluster node ls
meister --profile cloud node ls --cluster cluster-1
```

The discovery document at `/apis/meister.io/v1` advertises resources, kinds, verbs
and subresources. Generic `ls`, `get`, `rm` and `apply` use those descriptions.
Unknown kinds can still render metadata columns. `--tenant` scopes cloud requests;
cluster endpoints do not maintain the cloud tenant directory.

Convenience commands create resources or patch selected fields. `vm create -f`
reads a bare agent `NewVmSpec`; `apply -f` reads API objects with `apiVersion`,
`kind`, `metadata` and `spec`. Do not interchange these file shapes.
`apply` creates absent objects and replaces existing ones using their current
resource version. It is not a field-ownership or declarative merge engine.

## Lifecycle and output

- `vm start`, `stop`, `pause` and `resume` update desired run strategy. Read status
  to determine whether the agent completed the change.
- `vm attach` and `detach` read and replace the complete volume list. The boot
  entry is protected. Concurrent list edits can currently overwrite each other.
- `vm reschedule` clears placement for a stopped VM. Live migration is a separate
  `VmMigration` operation; the cloud forwards its creation to the owning cluster.
- Cordon blocks new placement. Drain also requests supported evacuation; some
  guests remain when locality or evacuation policy prevents a move.
- Delete requests can leave objects terminating while finalizers wait for cleanup.
  A successful command does not mean the underlying bytes or process are gone.
- Tables are for people. Use `-o json` for structured reads; fields containing spaces
  make whitespace splitting unreliable. `apply` currently emits no aggregate JSON
  result, even with `-o json`.
- Destructive commands request confirmation unless `--yes` is set; noninteractive
  callers must pass it explicitly. Confirmation is distinct from dry-run.

Logs are filtered on the node before applying the line limit. `vm logs` prints
recorded output; `vm console` opens an interactive WebSocket connection. Console
upgrade and fragmentation defects remain documented in the source review; a
working REST connection does not establish a working console path.

## Login

`meister login` creates a local key and CSR, submits the request and polls for an
issued certificate. The configured mTLS destinations take precedence over default
files under the config directory. The current implementation saves the key only
after issuance: if approval outlasts the command, that invocation cannot resume
with the same private key. A later login creates another request.

`meister login --oidc` uses the provider's device flow and stores a local session.
Later commands refresh sessions considered expired. Current limits:

- Cached sessions are checked against issuer and client ID during refresh, not
  when an unexpired token is loaded. Remove the old session when changing those
  profile settings.
- The cache uses the response lifetime even when sending an ID token. An earlier
  ID-token expiry can cause a 401 without an automatic retry.
- Secret file creation requests restrictive permissions, but replacing an existing
  file does not necessarily tighten its mode. Inspect existing credential files.

## Dry-run limits

The global `--dry-run` appends `dryRun=All` to controller POST, PUT and PATCH
requests. It is **not a general no-side-effect mode**:

- DELETE requests, direct agent commands and login do not consistently honor it.
- Server handlers must implement preview correctly. With CSR auto-approval enabled,
  CSR creation can sign a certificate and update the user directory before the
  preview branch.
- Discovery, authentication and credential refresh still involve reads or local
  credential updates.

Do not use this flag to establish that arbitrary commands are harmless. These are
known behavior gaps recorded for future fixes; this documentation review does not
change their implementation.

## Local agent

```sh
meister --endpoint unix:///run/meisterstack/agent/agent.sock agent vm ls
meister --endpoint unix:///run/meisterstack/agent/agent.sock agent vm observe <id>
```

Local commands use node-assigned VM IDs, not controller resource names. They can
inspect and reconcile actual processes. Socket ownership controls access; this is
an administrative interface, not tenant authorization. `agent volume` is read-only.
Standalone guests use inline disks from their VM spec.

## Source map

| Concern | Source |
| --- | --- |
| Command tree and dispatch | [main.rs](../components/cli/src/main.rs) |
| Profiles and credential selection | [config.rs](../components/cli/src/config.rs) |
| HTTP transport and preview query | [client.rs](../components/cli/src/client.rs) |
| Discovery and generic mutation | [generic.rs](../components/cli/src/generic.rs) |
| Enrollment and OIDC session | [login.rs](../components/cli/src/login.rs), [oidc.rs](../components/cli/src/oidc.rs) |
| VM, node and local operations | [vm.rs](../components/cli/src/vm.rs), [cluster.rs](../components/cli/src/cluster.rs), [agent.rs](../components/cli/src/agent.rs) |
| Resource tables and rendering | [nouns/](../components/cli/src/nouns/), [output.rs](../components/cli/src/output.rs) |

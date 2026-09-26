# CLI

`meister` addresses cloud/cluster resources through discovery. `meister agent …`
uses the local Unix API without discovery.

## Target and credentials

| Setting | Resolution order |
| --- | --- |
| Config | `--config` → `MEISTER_CONFIG` → existing `$XDG_CONFIG_HOME/meisterstack/config.toml` or `~/.config/meisterstack/config.toml` → `/etc/meisterstack/cli.toml` |
| Profile | Explicit selection / `MEISTER_PROFILE` → `default_profile` |
| Endpoint | Explicit endpoint / `MEISTER_ENDPOINT` → profile endpoint |
| Relative paths | Relative to the selected config directory |
| Token override | `MEISTER_TOKEN` overrides profile credentials |

Profiles contain `endpoint`, optional `ca_cert`, `credential` and `timeout_secs`.

| Credential | Source |
| --- | --- |
| `none` | Anonymous request |
| `token_file` / `env` | File / named environment variable |
| `command` | Token from an executed argument vector |
| `mtls` | Certificate and private key |
| `oidc` | Cached device-flow session; refresh when considered expired |

- HTTPS controllers require an explicit CA; OIDC providers can use public roots.
- Include endpoint ports, e.g. `https://cloud.example:3000`.
- See [configuration](CONFIGURATION.md) and [authorization](SECURITY.md).

## Commands and document shapes

```sh
meister --profile cloud api-resources
meister --profile cloud whoami
meister --profile cloud -t lab vm ls
meister --profile cluster node ls
meister --profile cloud node ls --cluster cluster-1
```

| Operation | Behavior |
| --- | --- |
| Generic `ls`, `get`, `rm`, `apply` | Uses discovered kinds, verbs and subresources |
| `vm create -f` | Reads a bare agent `NewVmSpec` |
| `apply -f` | Reads API objects; creates or replaces using current resourceVersion; no field-ownership merge |
| `--tenant` | Narrows cloud requests; does not change authorization |
| `vm start/stop/pause/resume` | Changes run strategy; status establishes progress |
| `vm attach/detach` | Replaces the volume list, protecting the boot entry; concurrent edits can overwrite each other |
| `vm reschedule` | Clears placement for a stopped VM; live migration is a separate resource |
| Cordon / drain | Blocks new placement / requests evacuation subject to locality and policy |
| Delete | Can leave a terminating object until finalizers complete |
| `-o json` | Structured reads; `apply` currently emits no aggregate JSON result |
| `--yes` | Supplies destructive-command confirmation, including noninteractive use |

`vm logs` reads saved output, filtered on the node before the line limit.
`vm console` uses WebSocket; REST success does not validate console upgrades or
fragment handling. See [console limits](SECURITY.md#secrets-console-tickets-and-quotas).

## Login and dry-run limits

- Certificate login: create key/CSR, submit, poll, then save credentials. A timeout
  before issuance loses that invocation's unsaved key; later login creates a new CSR.
- OIDC login: device flow and local session cache. Issuer/client binding is checked
  during refresh, not when loading an unexpired token.
- Cache lifetime can outlast an ID token; a resulting 401 has no automatic retry.
- Replacing an existing credential file does not necessarily tighten its permissions.

### Dry-run limits

`--dry-run` adds `dryRun=All` to controller POST/PUT/PATCH. It does not consistently
cover DELETE, agent commands or login. Credential refresh can still update files.
CSR auto-approval also signs and updates User history before checking preview.
The flag is not a general no-side-effect mode.

## Local agent

```sh
meister --endpoint unix:///run/meisterstack/agent/agent.sock agent vm ls
meister --endpoint unix:///run/meisterstack/agent/agent.sock agent vm observe <id>
```

- Uses node VM IDs, not controller names; socket permissions grant administrative access.
- `agent volume` is read-only. Standalone guests use inline disk specifications.

## Source map

| Concern | Source |
| --- | --- |
| Commands / transport | [main.rs](../components/cli/src/main.rs), [client.rs](../components/cli/src/client.rs) |
| Profiles / login | [config.rs](../components/cli/src/config.rs), [login.rs](../components/cli/src/login.rs), [oidc.rs](../components/cli/src/oidc.rs) |
| Discovery / rendering | [generic.rs](../components/cli/src/generic.rs), [nouns](../components/cli/src/nouns/), [output.rs](../components/cli/src/output.rs) |
| VM / node / local operations | [vm.rs](../components/cli/src/vm.rs), [cluster.rs](../components/cli/src/cluster.rs), [agent.rs](../components/cli/src/agent.rs) |

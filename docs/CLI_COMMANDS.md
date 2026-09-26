# Meister command map

Use [the CLI guide](CLI.md) for complete examples. `meister <command> --help`
provides the exact flags, required arguments and defaults for the installed binary.
A command's presence does not imply the selected endpoint serves it: check
`meister api-resources` first.

## Complete command tree

Each row names a command group and all its direct children. `help` and `--help`
are available for parser guidance. `meister deploy …` delegates to a separate binary.

| Group | Commands |
| --- | --- |
| `meister` | `vm`, `node`, `cluster`, `tenant`, `user`, `csr`, `image`, `floatingpool`, `floatingip`, `routedsubnet`, `providernetwork`, `router`, `storagepool`, `volume`, `secret`, `volumesnapshot`, `vmmigration`, `events`, `apply`, `api-resources`, `whoami`, `login`, `agent`, `deploy` |
| `meister vm` | `ls`, `get`, `rm`, `create`, `start`, `stop`, `pause`, `resume`, `logs`, `connect`, `attach`, `detach`, `reschedule`, `migrate`, `evacuation`, `events` |
| `meister node` | `ls`, `get`, `cordon`, `uncordon`, `drain`, `undrain`, `accepts`, `label` |
| `meister cluster` | `ls`, `get`, `cordon`, `uncordon`, `drain`, `undrain`, `label` |
| `meister tenant` | `ls`, `get`, `rm`, `create`, `quota` |
| `meister user` | `ls`, `get`, `rm`, `create`, `set-role` |
| `meister csr` | `ls`, `get`, `rm`, `approve`, `deny` |
| `meister image` | `ls`, `get`, `rm`, `create` |
| `meister floatingpool` | `ls`, `get`, `rm`, `create`, `quota` |
| `meister floatingip` | `ls`, `get`, `rm`, `create`, `assign` |
| `meister routedsubnet` | `ls`, `get`, `rm`, `create` |
| `meister providernetwork` | `ls`, `get`, `rm`, `create` |
| `meister router` | `ls`, `get`, `rm`, `create` |
| `meister storagepool` | `ls`, `get`, `rm`, `create`, `quota` |
| `meister volume` | `ls`, `get`, `rm`, `create`, `resize` |
| `meister secret` | `ls`, `get`, `rm`, `create` |
| `meister volumesnapshot` | `ls`, `get`, `rm`, `create` |
| `meister vmmigration` | `ls`, `get`, `rm` |
| `meister agent` | `vm`, `volume` |
| `meister agent vm` | `ls`, `get`, `rm`, `create`, `start`, `stop`, `pause`, `resume`, `logs`, `observe`, `reconcile` |
| `meister agent volume` | `ls`, `get` |

## Choose the endpoint

| Target | Use |
| --- | --- |
| Cloud HTTP(S) | Tenant/user/CSR administration, global resources and cluster placement |
| Cluster HTTP(S) | Cluster-local resources and node placement; node commands need no --cluster |
| Cloud node command | Add `--cluster <name>` to select the cluster |
| Agent Unix socket | Only `agent vm …` and `agent volume …`; administrative access by socket permissions |
| Deployment repository | [MeisterDeploy](../tools/meister-deploy/README.md); Nix/SSH fleet lifecycle |

## Global options

| Option | Purpose |
| --- | --- |
| `-p, --profile` | Select a configured endpoint and credentials |
| `--config` | Select the CLI TOML file |
| `--endpoint` | Override the profile endpoint |
| `-t, --tenant` | Scope cloud requests; does not grant access |
| `-o, --output table\|json` | Choose rendering; `apply -o json` has no aggregate JSON result |
| `--yes` | Confirm commands that otherwise prompt |
| `--dry-run` | Preview supported controller writes; [limitations](CLI.md#dry-run-limits) apply |
| `-v`, `-vv` | Increase diagnostics on stderr |
| `--version` | Print the CLI version |

## Common tasks

| Task | Start here |
| --- | --- |
| Connect and authenticate | [Profiles and first connection](CLI.md#first-connection) |
| Create and inspect a VM | [VM lifecycle](CLI.md#vm-lifecycle) |
| Attach persistent data | [Volumes and snapshots](CLI.md#volumes-and-snapshots) |
| Apply declarative resources | [Resource files](CLI.md#resource-files) |
| Explain placement or failure | [Troubleshooting](CLI.md#troubleshooting) |
| Run without controllers | [Local agent](CLI.md#local-agent) |
| Install or upgrade hosts | [Deployment guide](../tools/meister-deploy/docs/DEPLOYMENT.md) |

`vm connect` opens the serial console; there is no `vm console` command.
`agent vm` uses local VM IDs. Controller commands use resource names.

Sources: [parser](../components/cli/src/main.rs),
[dispatch](../components/cli/src/generic.rs), [noun handlers](../components/cli/src/nouns/).

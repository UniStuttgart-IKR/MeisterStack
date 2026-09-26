# MeisterDeploy

NixOS fleet deployment from a committed operator repository: resolve systems,
build and sign a release, inspect a plan, then apply it with recorded evidence.
SSH trust, service credentials, disk installation and workload verification have
separate steps and approvals.

| Need | Read |
| --- | --- |
| Every command and its effects | [Command map](docs/COMMANDS.md) |
| First deployment, upgrades and recovery | [Deployment walkthrough](docs/DEPLOYMENT.md) |
| One standalone agent and local CLI | [Single node](docs/SINGLE_NODE.md) |
| Cloud, cluster and compute hosts | [Multi-node fleet](docs/MULTI_NODE.md) |
| Inventory, IDs, planning, quorum, readiness and state | [Deployment model](docs/MODEL.md) |
| Effects, SSH, source pinning, resume and PKI | [Execution](docs/EXECUTION.md) |
| Builds, installation, activation, probes and verification | [Host operations](docs/HOST_OPERATIONS.md) |
| Runtime installation and CLI usage | [MeisterStack deployment](../../docs/DEPLOYMENT.md), [CLI guide](../../docs/CLI.md) |

## Build

From the MeisterStack checkout:

```sh
cargo build --locked -p meister-deploy --bins
./target/debug/meister-deploy --help
./target/debug/meister-activate --help
./target/debug/meister-install --help
```

`nix build .#meisterstack` packages these binaries with the runtime and `meister`.
`meister deploy …` delegates to `meister-deploy`. The target normally receives
`meister-activate` through its system package; `meister-install` runs on installation
media. There is no deployment daemon or central deployment service.

## Boundaries

- Inventory and plans express intent; observations and receipts record evidence.
- IDs bind selected inputs. A matching ID does not prove live host readiness.
- Timeouts and lost replies require inspection and reconciliation.
- System rollback does not restore application data or certificate reader state.
- Keep `.meister-deploy/`, target transaction records and trusted host-key evidence
  when recovering interrupted work.

These guides describe the reviewed source. The September 2026 review ran local
Rust tests and parser checks; it did not perform a real fleet deployment. Known
operational limits are stated beside each mechanism. Detailed findings and future
refactoring prompts live in the sibling MeisterStack-Journal repository.

# Documentation

> [!NOTE]
> This documentation was revised with Codex assistance during the September 2026
> source review. It is a source-based account, not a formal proof or a record of
> successful hardware experiments. See [AI guidelines](AI_GUIDELINES.md).

Read [architecture](ARCHITECTURE.md) first, then follow the mechanism you need.

| Area | Guide | Main source |
| --- | --- | --- |
| Purpose and tradeoffs | [Motivation](MOTIVATION.md) | Project design |
| Tiers, ownership and data flow | [Architecture](ARCHITECTURE.md) | `components/`, `shared/` |
| Reconciliation, placement and sessions | [Control plane](CONTROL_PLANE.md) | `components/{cloud,cluster}-controller/` |
| Local state and VM lifecycle | [Agent](AGENT.md) | `components/agent/` |
| VMM, devices and backend contracts | [Drivers](DRIVERS.md) | `drivers/`, `shared/agent-api/` |
| Discovery, objects and mutation | [API](API.md) | `shared/controller-api/`, `shared/proto/` |
| Profiles, commands and output | [CLI](CLI.md) | `components/cli/` |
| Identity, credentials and authorization | [Security](SECURITY.md) | `shared/pki/`, `shared/oidc/` |
| Overlay, routed and provider networks | [Networking](NETWORKING.md) | `drivers/linux-network/` |
| Volumes, images and snapshots | [Storage](STORAGE.md) | `drivers/{filesystem,lvm-thin,nfs,nvmeof,nvmeof-import}/` |
| Migration evidence and restart | [Migration](MIGRATION.md) | Cluster migration and agent provision modules |
| Resource ownership during cleanup | [Resource lifecycle](RESOURCE_LIFECYCLE.md) | Agent teardown and driver cleanup |
| Configuration and paths | [Configuration](CONFIGURATION.md) | `config/`, component config modules |
| Nix packages, modules and inventory | [Nix](NIX.md) | `flake.nix`, `nix/` |
| Installation and operation | [Deployment](DEPLOYMENT.md) | `templates/`, `examples/`, `scripts/` |
| Logs, traces and metrics | [Observability](OBSERVABILITY.md) | `shared/telemetry/` |
| Test layers and evidence limits | [Testing](TESTING.md) | Rust tests, `nix/tests/`, `deploy/chaos/` |
| Dependencies and their roles | [Technology stack](TECHSTACK.md) | `Cargo.toml`, `flake.lock` |

## Reading conventions

- **Spec** records desired state. **Status** records controller or agent observations.
- Acceptance of a request does not imply completion of its side effect.
- A timeout or missing report is not proof that an operation stopped.
- A source link explains implementation; a named test establishes only its tested
  inputs and assertions. Integration claims need separate experiment records.
- Historical diagrams in `diagrams/` are design artifacts. The architecture guide's
  diagrams describe the current component relationships.

API discovery and generated schemas are the reference for accepted resource shapes.
Configuration examples illustrate particular modes; they are not interchangeable
production defaults. The deployment tool under `tools/` is outside this review.

Detailed review findings, coverage ledgers and experiment notes live in the sibling
`MeisterStack-Journal` repository. Product guides retain operational limits where
needed to understand a mechanism.

# MeisterStack

MeisterStack orchestrates virtual machines, storage and networks across lab and
research clusters. A cloud controller manages tenants and cluster placement;
cluster controllers schedule nodes; agents manage local Linux resources and VMMs.
The project is research software in the alpha stage.

The runtime is written in Rust. Drivers are compiled into the agent and configured
at startup. Supported paths include Cloud Hypervisor, Linux networking, local and
shared storage, PCI passthrough and NVIDIA GPU sharing through Project Leandro.
Feature availability depends on the build, host and driver configuration.

## Start here

- [Documentation index](docs/README.md): mechanisms, operation and source map.
- [Architecture](docs/ARCHITECTURE.md): ownership, data flow and component boundaries.
- [Deployment](docs/DEPLOYMENT.md): runtime prerequisites and operating modes.
- [CLI walkthrough](docs/CLI.md), [command map](docs/CLI_COMMANDS.md) and [configuration](docs/CONFIGURATION.md).
- [MeisterDeploy](tools/meister-deploy/README.md): NixOS single-node and multi-node deployment guides.
- [Migration](docs/MIGRATION.md): recovery contract and known implementation gaps.
- [Testing](docs/TESTING.md): what each test layer establishes.

Build the runtime binaries from the locked workspace:

```sh
cargo build --locked -p meister-agent -p meister-cluster-controller \
  -p meister-cloud-controller -p meister-cli
```

Use the [Nix development environment](docs/NIX.md) for the pinned host tools and
build dependencies. Building the binaries does not provision a host or start a
cluster. Review [deployment prerequisites](docs/DEPLOYMENT.md) before running an
agent: it manages privileged processes, devices, storage and network interfaces.

The controller APIs expose discovery through `meister api-resources`. Start with
`meister --help`; use an explicit profile or endpoint for each operating mode.
Example configuration is in [config/](config/README.md).

## Project status

The source contains deterministic tests and privileged integration tests. A passing
unit suite does not establish hardware compatibility, safe recovery under every
failure, or production readiness. Documentation distinguishes implemented behavior,
design goals and unresolved limits; the migration receive path still has known
timeout and restart gaps.

`tools/meister-deploy` supplies deployment tooling. Its guides cover installation,
planning, credentials, upgrades and recovery, including known implementation limits.
No live deployment was performed for this documentation.

MeisterStack is developed as a master's thesis project at the University of
Stuttgart, IKR. See [acknowledgements](docs/ACKNOWLEDGEMENT.md) and
[AI contribution guidance](docs/AI_GUIDELINES.md). Licensed under [MIT](LICENSE).

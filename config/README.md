# Configuration examples and fixtures

| Path | Purpose |
| --- | --- |
| [examples](examples/) | Editable component TOML examples. |
| [examples/hardened](examples/hardened/README.md) | mTLS examples with a public cloud API and internal session endpoints. |
| `*.dev.toml` | Checkout-only development fixtures with relative paths and lab addresses. |
| [json](json/README.md) | VM specifications used by parser tests and as starting points for local guests. |
| `data/`, `pki/` | Ignored local credentials and login output. |

Read [Configuration](../docs/CONFIGURATION.md) for loading rules, identities,
backends, scheduling, and CLI profiles. Relative paths resolve against the
selected configuration file's directory. Do not copy development fixtures onto
a deployed node without replacing those paths and addresses.

Prose uses `# `; disabled settings use `#key = ...`. Keep optional top-level keys
above the first table. Component tests parse the examples and selected disabled
settings. `--check-config --config <file>` validates component configuration
without starting the service; runtime checks still need the target host.

[Nix modules](../docs/NIX.md) render the same configuration types from defaults,
inventory-generated values, and explicit role settings. The files here are
examples rather than a complete field schema.

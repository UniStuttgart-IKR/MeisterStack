# MeisterStack CLI

The `meister` binary talks to cloud and cluster REST APIs or a local agent Unix
socket. Controller discovery determines available resources and verbs.

See the [CLI guide](../../docs/CLI.md) for profiles, authentication, command behavior
and limits. Example profiles are in [config/](../../config/README.md).

```sh
cargo test --locked -p meister-cli
cargo run --locked -p meister-cli -- --help
```

Source layout: `main.rs` defines commands; `config.rs`, `client.rs` and `oidc.rs`
resolve connections; `generic.rs` handles discovery and generic resources;
`vm.rs`, `cluster.rs`, `agent.rs` and `nouns/` implement resource commands;
`output.rs` renders responses.

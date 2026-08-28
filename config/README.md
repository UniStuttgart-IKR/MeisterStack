# config/

Two kinds of file live here, and telling them apart matters more than it
looks: one kind is meant to be copied onto a machine, the other is meant to
be run from this checkout and would be wrong anywhere else.

| Path | Kind | Copy it? |
|------|------|----------|
| `examples/*.toml` | **Template.** One curated, fully commented file per component. | Yes — that is what they are for. |
| `examples/hardened/` | **Template.** The same four components configured for a deployment that is reachable from outside a lab. | Yes. Start from `examples/hardened/README.md`. |
| `*.dev.toml` | **Local dev.** Relative paths into this checkout, no credentials, no TLS. | No. |
| `json/*.json` | **Fixtures.** VM specs for `meister … vm create -f` and for the parser tests. | Only as a starting point for a spec of your own. |
| `data/`, `pki/` | **Key material.** Where `cli.dev.toml`'s CA path and `meister login`'s output land, because relative paths resolve against this directory; git-ignored. | No. |

## The templates

Four components, four files, plus the hardened variant of all four:

- `examples/agent.toml` — the node agent.
- `examples/cluster.toml` — one cluster's control plane.
- `examples/cloud.toml` — the public tier.
- `examples/cli.toml` — the CLI's profiles.

Each is a real, parseable config with every optional key present as a
commented-out line. The convention is mechanical, because tests in the four
components enforce it:

- Prose is `# ` — a hash and a space.
- A commented-out setting is `#key = …` — a hash and the key, no space.
- So "uncomment the settings, leave the prose alone" is one rule, and every
  commented-out key is parsed in CI as though it had been uncommented. A key
  renamed in the code fails there rather than on a node at start-up.
- Commented-out **top-level** keys go before the first `[table]` header, for
  the same reason: uncommenting one that sits below a table would move it
  into that table.

Relative paths inside a config resolve against **that config file's own
directory**, so a config and its `pki/` directory can be moved as one unit.

## The dev files

`agent.dev.toml` and `cli.dev.toml` are what this repository runs against
itself — `../data`, `../images`, `./bin`, a socket under `/tmp`. They are
loaded by tests (`config::tests::the_dev_config_in_the_repo_still_loads`) and
by `scripts/smoke.sh`, so they stay where they are and keep their names. They
are not templates: copying one onto a node produces an agent whose database
is two directories above wherever you put it.

`json/` holds VM specs rather than component configs — the body of a
`POST /vms`. Every `.json` in that directory is parsed by
`types::tests::every_spec_in_the_repo_still_parses`, which is why the
directory is a flat pile of specs and not a tree.

## The NixOS modules

`nix/` renders the same TOML from `meisterstack.<role>.settings`. Where a
module bakes a value that differs from what the examples here show, the
deviation is commented at the point it is made — see `nix/agent.nix`. The
binaries' own defaults are the tie-breaker: a key the code defaults is not
worth repeating in two more places.

# Testing and evidence

Use the smallest test scope that covers a change, then run the relevant workspace
suite. Keep complete logs and report skipped prerequisites separately from passes.
Comments and documentation are checked against source behavior; they cannot make an
unexecuted scenario successful.

## Test layers

| Layer | What it establishes | What it does not establish |
| --- | --- | --- |
| Pure Rust unit tests | Parsing, planning, policy and selected state transitions | Real host or distributed behavior |
| Agent tests with driver doubles and temporary redb | Orchestration, injected failures and process-restart records | Real VMM/backend timeout semantics or power-loss durability |
| etcd integration tests | Real revisions, transactions, watches and competing controller writes | Correct external side effects after a committed write |
| Privileged driver tests | Specific kernel, device, storage or VMM operations | Portability to untested hosts and arbitrary fault sequences |
| Nix evaluation/configuration checks | Module composition and selected generated values | Successful service startup or host installation |
| NixOS VM tests | The scripted boot, service and deployment scenarios | Real hardware, provider behavior or long-duration operation |
| Lab chaos harnesses | Observed behavior under their injected faults and oracle | Safety outside the observed inventory and failure model |

A test marked ignored is not a pass. Many etcd and privileged tests require a
pre-existing service, binary, kernel feature or device. Read the test's setup before
running it. Do not start the entire ignored suite against a working host.

## Runtime commands

The runtime workspace, excluding the deployment tool:

```sh
cargo test --locked --workspace --exclude meister-deploy --no-fail-fast
```

For a component change, select its package with `-p`. Cargo doc tests are part of
the relevant test targets; `cargo doc --locked --workspace --exclude meister-deploy
--no-deps` also checks documentation generation. Use a separate log for each run.
Neither command starts the lab chaos harnesses or NixOS VM tests.

For comment-only changes, compare parsed executable tokens or configuration values
with the pre-edit snapshot in addition to compiling. Preserve string literals,
feature flags, serialized fields, examples used as fixtures and generated inputs.
Documentation metadata such as CLI help should still satisfy help coverage tests.

## Script and documentation checks

- `bash -n scripts/*.sh` must be applied to each script individually; it checks
  shell syntax without executing host operations.
- `scripts/check-docs.sh` checks selected smoke field names, license assertions and
  ignored credential paths. Its recursive SPDX counts include untracked/cache
  content and do not reliably represent tracked source coverage. A failure requires
  inspection; a pass does not validate smoke command routing.
- `scripts/module-options.sh --check` builds generated Nix option metadata and
  compares the marked table in `deploy/README.md`. This can require Nix inputs and
  build work; it is not a plain Markdown check.
- Check local Markdown paths and anchors, parse configuration examples, and inspect
  diagrams for obsolete names. Link validity alone does not establish factual accuracy.
- `scripts/check-sign-csr.sh` and `check-ca-revoke.sh` exercise the CA tool with
  temporary keys and OpenSSL. The CA tool is outside the current runtime review.

`scripts/smoke.sh` needs a running agent even in its default mode. Its current
command drift includes missing `vm` segments under `agent`; field-name checks do
not catch that. Its optional lifecycle and NVRM sections create guests and have
incomplete failure cleanup. Do not cite it as a passing current regression suite
without repairing and rerunning it in an isolated environment.

## Recovery tests that still matter

Migration tests must separate controller timeout, transport timeout and VMM API
timeout. The existing planner tests do not cover the receive adapter's conversion
of timeout into failure or adoption of a surviving receiver after restart. See
[migration](MIGRATION.md) for the exact gaps.

Cleanup tests need the interleaving, not only the final happy-path state: hold an
attachment while delete waits; interrupt provisioning before and after handle
persistence; fail detach while a writer remains; reopen the store and retry.
Use explicit barriers, injected outcomes and clocks instead of elapsed sleeps where
possible. A temporary database reopen is a process restart test, not a simulated
power loss.

For thesis experiments, record commit, host/kernel/VMM/backend versions, configuration,
initial state, injected fault, observation interval, expected invariant, raw logs and
remaining resources. Separate a reproduced defect from a source-derived hypothesis,
and separate performance measurements from correctness evidence.

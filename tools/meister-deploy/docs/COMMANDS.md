# Deployment command map

Use `COMMAND --help` for exact arguments and defaults. These are three binaries
from the `meister-deploy` package; [the deployment guide](DEPLOYMENT.md) explains
when to use them. `meister deploy …` forwards to `meister-deploy` beside the CLI
binary or on PATH.

## Complete command tree

| Group | Commands |
| --- | --- |
| `meister-deploy` | `schema`, `init`, `inventory`, `validate`, `resolve`, `build`, `image`, `install`, `plan`, `gc`, `status`, `check`, `apply`, `report`, `verify`, `keys`, `retire` |
| `meister-deploy keys` | `enroll`, `csr`, `issue`, `revoke`, `rotate`, `import` |
| `meister-activate` | `status`, `stage`, `activate`, `confirm`, `revert`, `txn`, `lock`, `gc`, `keygen`, `keys` |
| `meister-activate txn` | `list`, `show`, `retire` |
| `meister-activate lock` | `acquire`, `release`, `take-over`, `show` |
| `meister-activate keys` | `status`, `switch`, `revert`, `remove` |
| `meister-install` | `confirm` |

## Workstation commands

| Command | Inputs → result | Effects / boundary |
| --- | --- | --- |
| `init DIR` | Embedded template → operator repository | Writes new files; attempts `nix flake lock` |
| `inventory -f FILE` | Inventory → merged settings/table or JSON | Reads local files |
| `validate` | Inventory or Nix/resolved contract → validation result | `--nix` also evaluates inventory; does not build systems |
| `schema KIND` | Contract name → JSON Schema | Local output |
| `resolve` | Committed source + Nix evaluation → resolved manifest | Evaluates Nix; `--from` accepts supplied evaluation with separate provenance |
| `build` | Resolved manifest → signed/measured release | Nix build/sign; optional cache upload and repeated-build check |
| `image` | Release + host + kind → media record/file | Builds installer, disk or direct-boot derivation |
| `plan` | Release + selected hosts + observations → plan | Normally probes SSH and saves evidence; inspect blockers and approvals |
| `install` | Install plan + release + approval → installer ISO/sheet | Builds media; does not format the target |
| `status` | Manifest/release → current observations and checks | Reads hosts, saves local snapshot; exit 0 does not mean healthy |
| `check` | Same inputs → readiness verdict | Required checks determine command success; no test VMs |
| `apply` | Matching plan/release + approvals → journal and receipt | Locks, copies, credential delivery, activation and planned interruption |
| `report` | Run ID → saved/folded evidence | Local files; verification and deployment reports have different verdict behavior |
| `verify` | Release + suite + release approval → test evidence | Creates guests or runs RDMA measurements; cleanup has documented limits |
| `keys enroll` | Host + trusted fingerprint → known_hosts entry | Contacts SSH keyscan; inventory fingerprint update is manual |
| `keys csr` | Manifest + host/kind → saved CSR | Generates/reuses target-local key over SSH |
| `keys issue` | CSR + manifest + CA reference → certificate | Local signing; host delivery requires plan/apply |
| `keys import` | Explicit HOST=STEM mappings → public certificates | Local import/index rebuild; [current limits](EXECUTION.md) apply |
| `keys revoke` | Serial/host/refresh → CRL and delivery plan | Revocation is local until apply delivers it |
| `keys rotate` | Host + release → replacement key/certificate and plan | Preparation already writes target/local key material |
| `retire HOST` | Release + recorded certificates → retirement and CRL plan | Does not wipe target data or remove inventory entries |
| `gc` | Retention counts/ages → removed roots/evidence | Does not run Nix store GC; some completed runs remain protected |

Schema names: `nix-manifest`, `resolved-fleet`, `release`, `observation`,
`activate-status`, `targets`, `plan`, `status`, `receipt`, `journal-event`,
`check-result`, `verify`, `verify-ledger`.

## Target helpers

Normally `apply` drives `meister-activate` as root. Its `status`, `txn list/show`,
`lock show` and `keys status` commands inspect state; the remaining commands can
change systems, transaction ownership, credentials or retained generations.
`confirm` records an operator/executor decision; it is not an independent readiness test.

`meister-install confirm` runs on installation media and can format the selected
disk. It requires the embedded host ID and disk serial. Its `--dry-run` skips
formatting but can mount partitions read-only while inspecting installation marks.
See [host operations](HOST_OPERATIONS.md) before direct helper use.

## Selection, approvals and outputs

- Selectors: `all`, `host=ID`, `group=NAME`, `role=ROLE`, `profile=NAME`, `site=NAME`.
  Commas form a union; leading `!` excludes, e.g. `'all,!host=a1'`.
- Plan kinds: `upgrade`, `bootstrap`, `install`, `keys-revoke`, `retire`.
  `keys rotate` constructs rotation plans after preparing credentials.
- Apply approvals use `CLASS=PLAN_ID`. Verification uses `verify=RELEASE_ID`.
  Read the actual plan; do not reuse approval IDs across changed plans.
- `resolve`, `build` and `plan` print an ID when writing an output file; build/plan
  without `--out` print the document. Diagnostics normally go to stderr.
- `status --json` is a status report containing `.observation`; it is not directly
  an `observation/1` file for `plan --observation`.
- After argument parsing: 0 means completed/successful result, 1 failure, 2 blocked.
  Clap also uses 2 for invalid arguments. `status` and deployment `report` can exit
  0 while reporting failures. Use `check` or inspect the recorded outcome.
- **JSON limits:** `verify --json` prints a run-ID prefix; keys revoke/rotate and
  retire can print plan output before their summary. A legacy report without a
  plan copy can print a table despite `--json`. Do not treat these as one-document APIs.

## Preview and offline behavior

| Mode | Meaning |
| --- | --- |
| `--dry-run` | Command-specific preview; may perform read-class external commands |
| `plan --offline` | No live probe/output file; supplied observations may still be used |
| `status/check --offline` | Saved observations, not current host state |
| `resolve/build/image/install --offline` | Refused |
| `verify --offline` | Refused |
| `keys enroll --offline` | Refused; a live key must be compared with trusted evidence |

There is no global dry-run/offline switch shared by every subcommand. In particular,
read-class commands can have host-level effects; installer partition inspection is
one example. See [execution contracts](EXECUTION.md).

Sources: [CLI](../src/main.rs), [activation helper](../src/bin/meister-activate.rs),
[installer helper](../src/bin/meister-install.rs).

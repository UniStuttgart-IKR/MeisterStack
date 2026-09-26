# Execution contracts

Implementation reference for `meister-deploy`; see [commands](COMMANDS.md) for CLI syntax.
Paths below are relative to the operator repository unless marked as target paths.

## Effect admission and subprocesses

| Effect | Real | Dry-run policy | Offline policy |
| --- | --- | --- | --- |
| `Offline` | Allow | Allow | Allow |
| `Read` | Allow | Allow | Refuse |
| `NixEval`, `Build`, `LocalWrite`, `Key`, `TargetWrite` | Allow | Refuse | Refuse |

- Policies apply before subprocess spawn and local filesystem mutation.
- Effect classes are caller declarations, not a syscall sandbox. Read-class scripts
  must themselves be read-only; command-specific previews can inspect live hosts.
- Every command has explicit argv, effect and deadline. Environment is inherited
  unless `env_clear` is set. stdin is separate from displayed argv.
- Cancellation/timeout terminates the process group: SIGTERM, two-second grace,
  then SIGKILL. Cleanup runners can ignore cancellation but retain deadlines.
- Output is buffered; configured exact substrings are redacted in command/error
  formatting. Partial secret echoes and unrelated sensitive output are not covered.
- StrictFake checks an ordered command sequence. It models command results without
  reproducing live SSH, process behavior, filesystem durability or reboot semantics.

Sources: [run](../src/run.rs), [effects](../src/effects.rs),
[effect spelling guard](../tests/no_direct_effects.rs).

## SSH and transfer

| Setting | Contract |
| --- | --- |
| Host trust | `StrictHostKeyChecking=yes`; repository `known_hosts`; global file disabled |
| Authentication | Batch mode, `IdentitiesOnly=yes`, optional identity file |
| Connection | Ten-second connect timeout; 15-second keepalive interval, three missed replies |
| Forwarding | Agent and both X11 forwarding options disabled |
| Remote argv | Each argument quoted for the POSIX remote login shell |
| Nix transfer | `ssh-ng://` plus the same options in `NIX_SSHOPTS` |

- Other SSH client configuration can still apply. Host names may resolve through SSH.
- Nix splits SSH options on whitespace; paths requiring quoting are rejected.
- Recorded host-key fingerprints come from the first matching enrolled key, not
  from a TLS/SSH session attestation. SSH independently enforces host-key trust.
- Uploads send content on stdin into a private same-directory temporary; chown/chmod
  precede rename. Publication is atomic, but the remote script does not fsync files
  or directories, and failed uploads can leave temporary files.
- Stage copies the closure, checks the target toplevel NAR hash, then calls the helper.
  Destination substitution requires both release cache provenance and target
  substituters; target configuration chooses the cache and signature policy.

Source: [transport](../src/transport.rs), [stage and delivery](../src/execute.rs).

## Source and release identity

| Input | Recorded / enforced |
| --- | --- |
| Clean Git tree | HEAD revision, tree hash, inventory digest, locked flake inputs |
| Dirty tree | Refused unless `--dev` |
| Developer snapshot | Content hash over paths, entry kinds, execute bits, bytes/link targets |
| Provided evaluation | File provenance/digest; does not prove evaluation used the recorded source |
| Release | Exact evaluated host set and declared output paths; embedded resolved manifest |
| Artifact evidence | NAR hashes, sizes, signatures; SHA256 for boot/installer files |

Source fingerprints use `git:<revision>:<tree>` or `dev:<content-hash>`.

Developer snapshots:

- Include tracked and unignored files; exclude `.meister-deploy` regardless of ignore rules.
- Preserve symlinks without scanning their targets. Refuse secret-like filenames
  and PEM private-key headers within a valid UTF-8 prefix of at most 64 KiB.
  This is a heuristic, not a complete credential or dependency scan.
- Copy to `.meister-deploy/snapshots/<hash>/`; rehash copied files before writing
  the adjacent `<hash>.complete` marker.
- **Cached snapshots are trusted:** an existing marker bypasses content verification.
  Modified cached files can therefore be evaluated under an unchanged fingerprint.
  Incomplete snapshot directories are reused rather than cleared.
- Flake follows resolution is bounded; `flake.lock` is required.

Release IDs omit timestamps, build-environment provenance and check durations.
Pinned inputs and measured bit-identical rebuilds are separate claims. Content IDs
and journal digests detect inconsistencies; they do not authenticate an author.

Sources: [source](../src/source.rs), [release](../src/release.rs), [IDs](../src/ids.rs).

## Plan execution and ownership

1. Match the plan/release and required approvals; acquire workstation state ownership.
2. Attempt control-plane anchor locks using available frozen endpoints.
3. Execute hosts sequentially within each planned wave and actions in plan order.
4. Before guarded mutations, refresh the target and available selected Raft peers;
   compare against plan assumptions after excluding this run's own changes.
5. Record outcomes, release remaining locks, then persist the receipt.

| Stage | Evidence / boundary |
| --- | --- |
| Preflight | Recheck current hardware/capacity constraints |
| Stage | Transfer, remote NAR comparison, target helper staging |
| Deliver | Check planned digest before upload; inspect target digest or private-file metadata |
| Cordon/drain | Workstation `meister` CLI controls the cluster; explicit target VM count zero required |
| Activate | Fsync activation intent before helper invocation; inspect target state after lost SSH |
| Reboot | Journal pre-command boot ID when available; wait for desired booted system |
| Verify/confirm | Required readiness checks precede confirmation |
| Return host | Undrain before uncordon, retire transaction, release host lock |

Defaults: drain/reboot waits 600 s; activation settlement 120 s; polling 5 s;
copy command 3600 s; ordinary remote commands 120 s; helper commands 960 s.

- Unchanged hosts still run required readiness checks.
- A host failure stops later waves after the current wave is processed.
- Anchors remain held beyond their host's Unlock action until final cleanup.
  Unreachable/unavailable anchors are reported but do not stop execution; cross-checkout
  exclusion can be incomplete. A foreign held lock blocks the run.
- Observations outside the refreshed set remain those embedded in the plan.
- Post-reboot etcd waiting applies to database members whose group had a healthy
  member when planned. An entirely unhealthy bootstrap group skips that wait.
- Final lock release is best-effort. A completed receipt does not prove every
  remote lock was released; early persistence errors can also prevent finalization.

Sources: [executor](../src/execute.rs), [planner](../src/plan.rs), [state](../src/state.rs).

## Journals, receipts and restart

| File / state | Role |
| --- | --- |
| `.meister-deploy/runs/<run>/plan.json`, `release.json` | Frozen resume inputs |
| `journal.jsonl` | Sequenced events, action evidence and host transitions; append plus fsync |
| `receipt.json` | Folded selected-host outcomes, checks, journal digest, stop/handoff details |
| Target transaction record | Activation outcome used to resolve interrupted local actions |
| Target key record/files | Separate rotation state; not an activation transaction |

- Local atomic replacement writes/fsyncs a temporary, renames it, then fsyncs its
  parent. Exclusive publication writes complete contents before hard-linking the name.
- Journal append fsyncs the file. Newly created journal directory entries are not
  independently fsynced by append; filesystem crash guarantees remain relevant.
- Resume repairs a torn final journal event on disk before appending. Interior parse
  corruption fails; fold retains detected sequence/transition breaks in the evidence.
- Resume repeats safe preparation where appropriate; an unfinished activation is
  reconciled with the target. Missing/inconsistent transaction evidence requires recovery.
- A completed reboot is skipped. For unfinished reboot, a changed boot ID and desired
  booted system completes the evidence; changed ID with another system requires recovery.
  Without boot IDs, reconciliation falls back to booted-system evidence.
- Committed does not mean cleanup finished: ordinary resume checks successful Unlock.
- Provider reboot is a persisted handoff. The tool neither uploads the provider bundle
  nor starts/polls a hypervisor reboot; resume checks whether the requested system booted.
- A receipt includes every selected host, including untouched ones. Host-derived
  `outcome`, `stopped` and `waiting_for` must be interpreted together.
- Report can return saved evidence without live probes. A receipt reconstructed from
  a journal lacks executor-added stop/handoff fields; reporting is not a readiness check.

Sources: [receipt fold/resume tables](../src/receipt.rs), [journal I/O](../src/state.rs),
[report command](../src/main.rs).

## PKI and rotation

| Operation | Ownership / output |
| --- | --- |
| Enrollment | Compare scanned Ed25519 key with independently obtained fingerprint; replacement records a reason |
| CSR | Target helper generates/reuses a private key; repository receives the public CSR |
| Issue | Verify CSR signature and expected CN; local CA signs; plan/apply delivers certificate |
| CA location | Relative to inventory file; repository exclusion is lexical, not symlink-resolved |
| Public delivery | Digest-bound to plan; target digest verified |
| Private delivery | Presence/metadata only; existing private keys are not replaced |
| Target-generated key | No local delivery source |

Local public state: `pki/csr/<host>-<kind>.csr`,
`pki/issued/<host>/<kind>.crt`, rotation `<kind>.next.crt`/`<kind>.prev.crt`,
and shared `pki/crl.pem` (`kind` here is `identity` or `serving`).
Relative operator-file refs retain only the basename
under the resolved CA directory; deeper layouts are unsupported.

Identity CNs derive from roles and effective tier names: `system:node:<host>`,
`system:cluster:<tier>`, `system:cloud:<tier>`; serving certificates use the host name.
The rendered `secret_refs.source.ref` alone does not select the CSR subject.
Cloud, cluster and agent roles share `identity.key`/`identity.crt`; selecting one
identity kind on a mixed-role host does not provide authentication for every role.

Rotation sequence: prepare target next key → sign locally → upload next certificate →
switch helper file pair → restart running readers → verify → publish local active
certificate → remove target backups. The previous certificate remains valid until revoked.

Material limits:

- **Interrupted restart:** helper `Switched` state causes resume to begin at verify.
  A restart interrupted after the file switch can be skipped. Digest/unit checks
  do not prove a running process loaded the new certificate.
- Rotation rollback also ignores restart errors after restoring files; `rolled-back`
  does not establish that each process reloaded the restored identity.
- Host-wide revocation lists active certificates only, excluding `.next`/`.prev` files.
  CRL delivery does not restart units; readers refresh on their own interval.
- Import validates described CN and sibling key permissions, not the CA chain or
  certificate/private-key match. It writes repository certificates before CA-directory
  validation. Index rebuild scans the CA directory, so external imports absent there
  are not automatically made revocable by serial.
- Retirement retains the known_hosts entry with a comment: this preserves history,
  not SSH revocation. Target erasure and inventory removal are separate operations.

Source: [PKI](../src/pki.rs), [rotation execution](../src/execute.rs),
[CLI issue/import](../src/main.rs), [CA index rebuild](../../meister-ca).

## Version and evidence bounds

- Resolved fleet, release, plan and receipt contracts currently use `/1` schemas.
  Typed readers check supported schemas; release/plan loading also checks content IDs.
- Helper transaction/key state has its own `/1` contract. Keep operator and target
  helper versions compatible; this is not a negotiated rolling protocol upgrade.
- Current tests include strict command models, isolated CLI shims, temporary OpenSSL
  CA imports and one network-namespace apply comparison. They do not establish
  power-loss durability, arbitrary concurrent-writer safety or live TLS reload success.

Sources: [manifest parsing](../src/manifest.rs), [activation helper](../src/activate.rs),
[executor tests](../src/execute/tests.rs), [CLI import tests](../tests/cli_import.rs).

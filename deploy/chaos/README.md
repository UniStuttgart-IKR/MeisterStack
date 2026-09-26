# Lab fault and measurement harness

These scripts exercise MeisterStack through REST and host shell commands. They
can stop services, kill VMMs, change agent configuration, create/delete resources
and alter host networking. Their default topology is the development lab. A clean
run is evidence about the exercised paths and available observations, not a proof
of durability, isolation or complete cleanup.

## Entry points and effects

Run commands from this directory; some output paths and subprocesses depend on the
working directory. Review the selected scenario before executing it.

| Entry point | Purpose and effects |
| --- | --- |
| `mini.py --list`, `scenarios.py --list` | List cases without contacting the fleet; imports create the output directory. |
| `mini.py M0` | Request discovery from every configured controller replica and check the returned tier. |
| `selftest.sh` | Generate a local CA, optionally build binaries, start etcd and both controllers, then exercise discovery and authentication. |
| `invariants.py --baseline` | Read REST and host state; replace the output directory's baseline. |
| `invariants.py` | Collect observations and append candidate violations and selected coverage gaps. |
| `scenarios.py S6` | Run a named scenario and then an invariant sweep. Effects vary by case. |
| `mini.py M1 --reps 6` | Run a named measurement; M1 uses persistent `mc-fs` and `mc-fs2` pool fixtures. |
| `chaos.py --seed 4711 --steps 150` | Mix resource operations and faults; `--no-faults` still writes resources and node intent. |
| `matrix.py --link A --cond L200 --load w1 --seed 4714 --n 20` | Apply one traffic fault and measure a workload. |
| `run-matrix.sh` | Run the predefined matrix, skipping cells whose result JSON already exists. |
| `fuzz.py --mode api --seed 5001 --rounds 200` | Send adversarial requests using the configured privileged credential. |
| `snapshot.sh`, `rollback.sh back` | Copy installed binaries to `.pre-chaos`, or replace binaries and restart remote services. |
| `rollback.sh forward` | Invoke `deploy/push.sh all`; this is a deployment operation. |

The untracked `durability.py`, when present, is an additional experiment that
partitions etcd peers and restarts controllers. Its endpoint-status probes alone
do not establish loss of write quorum. It is not part of the tracked harness.

## Topology, transport and fixtures

[REST endpoint configuration](invariants.py) accepts comma-separated
`CHAOS_CLOUD`, `CHAOS_CLUSTER1` and `CHAOS_CLUSTER2`; a set but empty value disables
that endpoint list. `CHAOS_CLOUD_PORT` and `CHAOS_CLUSTER_PORT` override REST ports.
These overrides do **not** retarget the complete harness: node names, SSH addresses,
cluster membership, session/etcd ports, network interface `eth0`, pool names and
several scenario addresses remain fixed in [operations](ops.py),
[invariants](invariants.py), [matrix workloads](matrix.py) and [scenarios](scenarios.py).
The invariant checker also indexes both named clusters in its etcd check, so a
single-cluster override can fail even though M0 supports that topology.

The [HTTP transport](mtls.py) uses `CHAOS_CA`, `CHAOS_CERT` and `CHAOS_KEY`, falling
back to files under `CHAOS_PKI_DIR` (default
`/mnt/vmstore/MeisterStack/labpki`). Defaults select the root break-glass identity.
If any credential file is absent, or `CHAOS_SCHEME=http`, it selects plain HTTP.
That fallback does not discover what the server supports. HTTPS validates the CA
chain but disables hostname verification. SSH uses the local `id_ed25519`, logs
in as root and disables host-key verification. These are lab trust assumptions.

VM fixtures expect `vmlinux.elf`, `tiny-initrd` and `tiny-volume.raw` to be available
to agents. Other cases assume the `fabric` pool, router `lab-out`, tenant `lab`,
provider wiring and a reachable floating address. Scenario titles include historical
bug descriptions; inspect the current predicate and prerequisites before treating
a title as a claim about the current product.

## Local transport selftest

`selftest.sh` needs etcd, etcdctl, OpenSSL and Python, plus Cargo or existing
controller binaries. It uses loopback ports 3800/3801, 50850/50851 and 23790/23791.
Building missing binaries may need network access. `MEISTER_CLOUD_BIN` and
`MEISTER_CLUSTER_BIN` select prebuilt executables.

The script recursively removes and recreates `CHAOS_SELFTEST_ROOT` (default
`/tmp/ms-chaos-controller`) and removes it on exit. The path must be disposable;
fixed paths and ports do not isolate concurrent runs. `KEEP=1` retains the files
and background services. No agents, VMMs or storage/network backends are started,
so this establishes controller transport/discovery behavior only. It does not test
VM provisioning, sibling forwarding, certificate revocation or fault recovery.

## Evidence and interpretation

Set `CHAOS_OUT` to a separate output directory per experiment. Most Python scripts
use it, but `run-matrix.sh` resumes from its literal `out/` and `phases.py` writes
`out/phases.json` relative to the working directory.

The baseline records existing taps, files, LVs, VNIs, redb sizes and selected probe
names. It is not a snapshot of all resources, original node settings, qdiscs or
service state. Recording it after a fault can hide existing residue.

| Artifact | What it records |
| --- | --- |
| `findings.txt` | Timestamp, check ID, tag, seed and candidate finding text. |
| `seq-<seed>.log` | Attempted seeded-loop operations and reported outcomes. |
| `baseline.json`, `coverage.txt` | Initial selected host state and some skipped checks. |
| `matrix-<cell>-<seed>.json`, `matrix.txt` | Per-cell samples, summary measurements and invariant flag. |
| `w3-ping-*.log` | Timestamped ping replies used for failover gap calculations. |
| `fuzz-<mode>-<seed>.json` | Fuzzer findings and generated reproduction hints. |

Several limits affect the meaning of those results:

- Observations are collected sequentially across REST and SSH. There is no common
  revision or timestamp snapshot; legitimate transitions can look inconsistent.
  Several failed API reads become empty lists, and not all missing observations
  appear in coverage output.
- `ops.wait_gone` currently treats every non-200 VM response as disappearance,
  including authorization and server errors. Verify a 404 before interpreting
  its result as deletion completion.
- I4 reports generic nonzero nft drop counters. Those counters show blocked
  traffic, without identifying a tenant or proving successful cross-tenant access.
  Missing or truncated nft output can also skip that check.
- A seed does not reproduce API-response branches or distributed timing.
  `chaos.py --replay N` samples only top-level verbs and does not replay the random
  draws consumed inside real operations. Use the sequence log as supporting evidence.
- Matrix W1 creates at the cloud without pinning the affected cluster. Placement
  around a fault can be correct behavior. The first established cluster-cloud TCP
  connection is not necessarily the selected speaker; `sessionEndpoint` changes
  identify a cloud endpoint, not every speaker change among cluster replicas.
- Ping gaps omit silence before the first and after the last reply. Percentiles
  describe successful collected samples; inspect failures, skipped cells, sample
  counts and raw observations separately.
- Fuzzer isolation/authz cases use the privileged transport and vary query/body
  fields rather than authenticating as separate tenant users. They do not prove
  tenant authorization. Generated curl hints truncate bodies and are not exact
  byte-for-byte reproductions. Restart counters do not by themselves prove a panic.
- `chaos.py`, `scenarios.py` and `matrix.py` can finish with status zero after
  recording findings; `fuzz.py` also does not make its finding count an exit code.
  `mini.py` and `invariants.py` return nonzero for reported findings. Inspect artifacts
  when automating runs. An existing matrix JSON is skipped even if its result failed.

## Fault lifetime and cleanup

Traffic shaping replaces the root qdisc; removal deletes it rather than restoring
its previous configuration. The shaper requests a delayed systemd cleanup timer,
but does not validate that timer creation succeeded. DROP rules use the shared
`inet chaos` table and have no automatic expiry. Python `finally` handles ordinary
unwinding, not a killed process; matrix shell timeouts can therefore leave DROP
rules behind. Do not overlap runs on the same hosts.

`chaos.py --cleanup` uses name, tenant and pool prefixes to delete selected
`chaos-*` resources and remove matching labels. It is not an ownership manifest,
and its kind lists omit some objects, including cloud snapshots and migration
records. It does not restore cordons, service state, config files or firewall rules.
`mini.py --cleanup` requests deletion of `mc-*` VMs, volumes and snapshots while
keeping its persistent pool fixtures; it neither waits for every delete nor removes
the tenant or node labels. The fuzzer uses additional `fz-*` and `fuzz-*` names.

Host effects are not confined to fixture prefixes. The seeded loop's heal step
uncordons known nodes. Mini M4 can reschedule an existing stopped/Failed VM without
a prefix filter. S14 rewrites an agent config, and several stop/drain scenarios lack
a `finally` restoration path. Inspect actual resources, services, configuration,
qdiscs and firewall state after a run, including failed or interrupted runs.

Binary rollback restores only the copied executables. It does not roll back API
schemas, etcd/redb data, credentials, configuration or kernel state, and its current
success check assumes twelve hosts. Repeating `snapshot.sh` overwrites the binary
backups. Compatibility and recovery requirements remain those of the product's
[control plane](../../docs/CONTROL_PLANE.md), [migration](../../docs/MIGRATION.md)
and [resource lifecycle](../../docs/RESOURCE_LIFECYCLE.md).

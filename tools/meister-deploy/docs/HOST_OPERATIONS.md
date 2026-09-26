# Host operations

Implementation reference; CLI syntax is in [COMMANDS](COMMANDS.md), planning in
[MODEL](MODEL.md), and workstation execution/recovery in [EXECUTION](EXECUTION.md).

## Build and image artifacts

Source: [build.rs](../src/build.rs), `Builder::realise`, `Builder::image`.

| Operation | Contract |
| --- | --- |
| Artifact build | Build derivations already recorded by resolution; no flake reevaluation |
| Batch | Deduplicate/sort system, package and direct-boot derivations; associate Nix JSON outputs by `drvPath` |
| Required build checks | Run distinct declared check derivations separately |
| Managed NixOS hosts | Require a signing key; context-only builds can omit one |
| Signing | One recursive signing command; require signatures on managed host toplevels |
| Measurement | NAR hashes/sizes/signatures, configuration SHA256, boot identity and optional direct-boot files |
| Reproducibility | Optional per-host rebuild; pinned source alone does not mean bit-identical output |
| Cache | Optional copy after signing/measurement; copy failure prevents release completion |
| Roots | State-backed builds create release GC roots; a builder without state does not |

- Normal artifact build deadline: four hours; signing: ten minutes; store queries:
  five minutes; cache copy: two hours. Each is a command deadline.
- Partial builds bind only the resolved subset. Failed builds may leave store outputs
  without producing a completed release.
- Signature presence does not independently establish the expected signing identity.

| Image kind | Result |
| --- | --- |
| `installer-iso` | Locate one ISO inside the declared derivation output; hash its bytes |
| `disk` | Locate one `.raw`, `.qcow2`, `.img`, `.vhd` or `.vmdk` candidate; hash its bytes |
| `direct-boot` | Directory with kernel, initrd and command-line artifacts for a provider |

Image building is separate from release building. It requires one derivation output
and, for file images, an unambiguous medium candidate. It can create a GC root/output
symlink and leaves the release unchanged. Media hashing reads the complete file into memory.

## Installation boundary

Source: [install.rs](../src/install.rs), `Installer::prepare`, `Installer::execute`;
[installer entrypoint](../src/bin/meister-install.rs).

- Workstation `meister-deploy install` prepares and records installation media.
  `meister-install` runs on that medium and formats the selected physical disk.
- Medium contract: `/etc/meister-install/target.json`, schema
  `meister-deploy/install-target/1`; binds one host, system, disk and disko layout.
- Default mount root: `/mnt`; mark probe: `/run/meister-install/probe`;
  installed mark: `/etc/meister-install/installed.json` on the target root.

| Preparation check | Refusal / limitation |
| --- | --- |
| Host and typed serial | Must match the medium's host and nonempty disk serial exactly |
| Kernel disk listing | Select whole disks by serial and optional operator WWN; reject ambiguity |
| Declared WWN and size | Enforce declared WWN; observed size must be within 2% |
| Layout devices | Every declared layout device must resolve to the selected whole disk |
| Installation mark | Probe direct child partitions; an existing mark requires `--reinstall` |
| Preserved devices | Validate declared persistence references against the selected disk and direct partitions |

Preservation checks resolve label/UUID/partition-label references. Other-disk serial
references and absent devices produce notes; resolver errors abort. No data is copied,
and arbitrary LVM/crypt/storage dependency graphs are not traversed.

**Physical installer dry-run still probes mounts.** `prepare` can create the probe
directory and mount partitions with `ro,nosuid,nodev`, then unmount them. The dry-run
flag is checked by `execute`. These mounts are classified as `Read`; they alter mount
state, and the options do not establish filesystem journal-replay suppression.
A dry-run policy can refuse probe-directory creation when that directory is absent.

After the caller prints and flushes the destruction summary, real execution performs:

1. Baked disko script: partition, format and mount; deadline 15 minutes.
2. `nixos-install --system … --root … --no-root-passwd --no-channel-copy`; deadline one hour.
3. Generate the installed ED25519 SSH host key and report its fingerprint.
4. Set up machine ID, atomically write the installation mark, recursively unmount.

There is no transaction rollback for a failed physical installation. A failure after
formatting can leave partial contents or mounts. The installer does not reboot.
UEFI hosts boot their installed disk after media removal; direct-boot hosts need the
provider to load the release's kernel/initrd/command line. Normal install planning
refuses GRUB targets, although the target helper retains an exhaustive GRUB branch.

First-install observation does not require a preexisting enrolled key: endpoint
construction accepts its absence, and `observe_host` records an unreachable host
without SSH. This supplies the planner with absence of contact, not proof of an
empty disk. The physical installer performs disk/mark checks before destruction.
Enroll the newly generated SSH fingerprint after boot; service certificates are a
separate enrollment step. See [observation.rs](../src/observation.rs) and
[observe.rs](../src/observe.rs).

## Target activation transaction

Source: [activate.rs](../src/activate.rs), `Helper::activate`, `confirm`, `revert`.

| State / record | Meaning |
| --- | --- |
| `txn/<id>.json` | Mode-0600 atomic transaction record under `/var/lib/meisterstack/deploy` |
| `pending` | Previous/desired systems recorded; confirmation still required |
| `confirming` | Confirmation intent persisted before timer disarm |
| `reverting` | Rollback intent persisted before restoring the profile |
| `confirmed`, `reverted` | Completed decision; eligible for normal retirement |
| `inconsistent` | Invalid record or failed recovery; requires explicit investigation |
| `txn/<id>.json.done` | Retired archive; written before deleting the live record |

`stage` checks store registration and `bin/switch-to-configuration`; it does not
rehash the closure or verify signatures. Workstation staging adds its own transfer
and hash checks; see [EXECUTION](EXECUTION.md#ssh-and-transfer).

Activation order: reject conflicting ownership/open records → capture previous
profile/generation → acquire the transaction decision lock → persist intent → arm
rollback → set profile → invoke `switch-to-configuration`.

| Mode | Activation / fallback |
| --- | --- |
| `switch` | Apply userspace immediately; rollback selects the previous profile and switches back |
| `boot` | Require systemd-boot and previous generation; keep old default and set new one-shot entry |

- A zero confirmation interval creates no rollback timer. Otherwise the transient
  timer invokes the helper; it does **not** survive reboot.
- Failed or overdue forward activation attempts immediate rollback; failed rollback
  leaves `inconsistent`. The decision lock prevents the timer racing that same transaction.
- `confirm` persists intent before disarming the timer. For boot mode it makes the
  current profile generation the default. It does not itself verify readiness,
  the running system, or that the new generation booted.
- `revert` can retry `reverting`; confirmed transactions refuse rollback. Overriding
  `confirming` requires operator force/reason. Boot rollback restores the entry but
  does not reboot the currently running kernel.
- Boot one-shot fallback applies on a subsequent reboot; this is not a host watchdog.
- Forced retirement permits only inconsistent records and retains audit fields;
  active staged/pending/decision records remain protected.

## Locking, collection and keys

Source: [activate.rs](../src/activate.rs), `records`, `read_lock`, `gc`, key methods.

| Mechanism | Scope |
| --- | --- |
| Host lock | Exclusive `lock/owner.json`; same run/operator can resume; no automatic expiry |
| Decision lock | `<txn>.deciding`; local PID liveness and rename-based stale reclamation |
| Timer contention | Retry every two seconds, bounded to 1,920 seconds |
| System GC | Refuse open transactions; retain profile generation, matching booted generation and newest N others |
| Archive GC | Retain newest N archive names lexicographically |
| Key rotation | `.next` preparation, four ordered renames into current/`.prev`, explicit retirement |

Material limits:

- Unreadable transaction files are skipped; readable malformed JSON becomes
  `inconsistent`. Malformed host-lock JSON appears absent to `read_lock`.
- Open-transaction inspection precedes the per-ID decision lock. Different direct
  helper transaction IDs are not serialized without the outer host-lock protocol.
- Current, booted and profile targets are distinct. `next_boot_system` reports the
  resolved profile; it is not a boot-loader default/one-shot inspection.
- Key/certificate pairs are not swapped atomically. Partial rename states are
  reported as inconsistent; file status does not attest a running service's key.
- System rollback does not roll back application data. Filesystem and reboot fault
  behavior needs separate host/VM validation; fake effects do not establish it.

## Observations and readiness

Source: [observe.rs](../src/observe.rs), [observation.rs](../src/observation.rs);
readiness rules: [MODEL](MODEL.md).

- Eight concurrent probes by default; one framed POSIX-shell SSH script per host,
  60-second SSH command deadline, no retries. Missing enrollment skips SSH entirely.
- Observe identity, current/booted/profile links, boot ID, unit states, exact mount
  points, credential metadata, etcd membership/health, PCI/MACs, capacity and devices.
- Public credential extensions are hashed; other files expose mode/owner metadata.
  Service enrollment requires declared identity keys and companion certificates.
- Agent VM count is the returned list length, without phase filtering. Missing or
  unsupported replies remain unknown. Agent socket defaults to
  `/run/meisterstack/agent/agent.sock`, overridable through `paths.run_dir`.
- Partial framing sets `unknown_reason`. Missing individual fields do not necessarily
  invalidate an otherwise framed response; empty collections can mean failed reads.
- Compatible helper status overlays shell observations. Raw transaction-file fallback
  expects the observation `Txn` shape, whereas the helper writes `TxnRecord`; pending
  on-disk transactions can therefore disappear when helper status is unavailable.
- Target adapters may replace addresses and carry opaque provider references; they
  cannot add fleet hosts or contradict a recorded fingerprint. Binding does not enroll SSH trust.

## Functional verification

Source: [verify.rs](../src/verify.rs), [tests](../src/verify/tests.rs).

| Suite | Work / current limits |
| --- | --- |
| `vm-lifecycle` | One canary then a batch per selected host; create, await Running, read serial marker, delete and verify absence |
| `gpu` | Up to two declared GPUs, five rounds, invalid-PCI refusal; in-guest visibility remains unknown and computation not applicable |
| `rdma` | SSH server/client `rping`, `ib_send_lat`, `ib_write_bw`; no performance thresholds |

- Defaults: batch 2, run 30 minutes, settle 120 seconds, polling 2 seconds, CLI 60
  seconds, fabric command 120 seconds, ten rping rounds, five-second perftest samples.
- VM placement is scheduler-controlled; selected-host iteration does not prove that
  every selected host ran a guest. Missing placement retains the requested host.
- Budget controls lifecycle batch size, not a global live-resource ceiling. Kept/lost
  guests accumulate, and GPU rounds do not use that budget.
- Normal creates persist run-tagged ownership first. Cleanup verifies absence using
  a valid JSON listing; unknown deletion becomes `lost`. Lost entries are not retried
  in the same pass. `--keep` skips deletion and blocks required lifecycle checks.
- GPU refusal records only accepted responses; failed/lost create responses can leave
  untracked resources. Any nonzero CLI exit currently counts as successful refusal.
- RDMA defaults pair equal first-three-octet storage-address strings, ignoring CIDR
  prefixes and IPv6. Explicit pairs validate host existence/applicability only.
- Pair requiredness comes from the server host. A missing fabric capability ends
  later pair processing. Background servers/logs are outside the VM ledger and have
  no durable crash cleanup; interrupted runs can leave them behind.
- `ledger.json` records resources; `verify.json` records results. Hardware evidence
  classification uses snapshot capabilities and an explicit mock flag, not runner
  detection or independent hardware attestation. Required failed/unknown/skipped
  checks block acceptance; optional failures can coexist with accepted results.

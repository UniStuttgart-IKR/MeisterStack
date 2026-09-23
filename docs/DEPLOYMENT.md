<!--
SPDX-License-Identifier: MIT
SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR
-->

# Deploying MeisterStack

**Provenance.** Written by the deploy-v1 lanes (M0–M5, L1–L3) and verified
against the tests named in each section. Every claim in this file points at
something that was executed: a NixOS VM test in `nix/tests/`, a Rust test in
`tools/meister-deploy/`, a shell check in `scripts/`, or a run against the
lab that is named as such. A sentence with no test behind it is not in this
file — where something is *not* verified, the text says so in those words.

The numbers in brackets are measured run times on `manacor` (AMD, KVM,
nixpkgs 25.11), not promises.

---

## 1. Nix or meister-deploy?

Nix says **what** should be on a machine. `meister-deploy` says **when** and
in **which order** it gets there, checks beforehand whether that is safe, and
afterwards proves what happened.

| You want to… | Use | Why |
|---|---|---|
| change what a host runs | edit the Nix files in **your** repository | the configuration is the repository; nothing else is |
| put that on one machine that is not in a fleet | `nixos-rebuild switch --flake .#host` | no ordering to get right, no quorum to lose, nothing to prove |
| put it on a fleet | `meister-deploy plan` → `apply` | waves, canaries, quorum, cordon/drain, locks, journal, receipt |
| install a machine that has no OS yet | `meister-deploy install`, then `meister-install confirm` **on the machine** | a disk is formatted by a person who read the serial off the sheet |
| let a new machine into the fleet | `meister-deploy keys enroll` | the fingerprint comes from the console, never from the network |
| give a host a certificate | `keys csr` → `keys issue` | the private key is made on the host; the CA key never travels |
| replace a key, take one back | `keys rotate`, `keys revoke` | five phases with a way back; a list every controller re-reads |
| make the fleet prove it works | `meister-deploy verify` | real guests through your own control plane, with a ledger |
| take a machine out of service | `meister-deploy retire` | certificates back, the fleet told, nothing deleted |
| fix a machine at 03:00 | `nixos-rebuild --target-host`, or `meister-activate` on the box | and then `status`, which will show the drift |

`meister deploy …` in the main CLI is a plain `exec` pass-through to this
binary (`components/cli/src/main.rs`), so the two spellings are the same
program.

**What Nix alone cannot do here.** It cannot know that three etcd members are
two at the moment (D8), that a kernel change means a reboot and a reboot
means an approval (V15), that a host's identity certificate is the one this
fleet issued (V09), or that a host came back with the same host key it went
down with. Those are the questions `plan` asks, and the answers are in the
plan before anything moves.

---

## 2. Guarantees

Each row: what is promised, how it is kept, where it stops, and the test that
was run.

| Guarantee | How | Where it stops | Test (measured) |
|---|---|---|---|
| Nothing is changed without a plan that was written down first | `plan` writes `plan.json`; `apply` takes a plan and nothing else | `--takeover` re-checks; it does not skip the check | `tests/cli_plan.rs`, `tests/cli_apply.rs` |
| An activation that is not confirmed is taken back | target-side transaction + `systemd-run --on-active` revert timer | switch-mode always; **boot-mode rollback only with systemd-boot** (grub has no `bootctl set-oneshot`) | `checks.vm-activate-semantics` (88 s); real ESP in `vm-install-blank-disk` (262 s) |
| Two operators cannot move the same fleet | lock directory per target host **and** on every control-plane host; operator lock in the repo during bootstrap | a lock is never released by a timeout — a stale one is `--takeover <run-id>`, which re-observes | `checks.vm-managed-update` (135 s), V18 |
| A host that already runs the release is not touched | `plan` compares three system facts (current, booted, next-boot) | an unreachable host is `unreachable`, never "unchanged" | V10/V11 planner tests; no-op reapply in `vm-managed-update` and in the lab |
| A reboot never happens without an approval | reboot class from kernel/initrd/cmdline vs. observation; `--approve reboot=<plan_id>` | conservative when unknown: unknown means reboot | `checks.vm-kernel-change` (77 s) — `boot_id` moves exactly once |
| A group never loses quorum | `etcdctl member list` + `endpoint health -w json` per member; allowed = floor((n-1)/2) − already unhealthy | a topology change (members, controller move) is `blocked`, not guessed | `checks.vm-quorum-degraded` (107 s), V14 |
| A disk is only formatted by a person at the machine | `meister-install confirm --host --disk <serial>`: serial/WWN/size from `lsblk -J`, unique or abort, install marker | ambiguous serial = abort; second boot of the medium does nothing without `--reinstall` | `checks.vm-install-blank-disk` (262 s), V07 |
| A host key is never accepted blindly | `keys enroll --fingerprint` compares what you typed against `ssh-keyscan`; transport is always `StrictHostKeyChecking=yes` with the repo's `known_hosts` | a different existing key is refused unless `--replace --reason` | `tests/ssh_is_strict.rs` (source-level, no exemptions), `checks.vm-keys-roundtrip` (70 s) |
| A private key never travels | key is generated on the target (`meister-activate keygen`); only the request comes back; the CA key stays with the operator | `keys import` looks at a key file and refuses to copy it | `checks.vm-keys-roundtrip`, `tests/cli_import.rs` (real CA) |
| A revoked certificate stops working without a restart | `RevocationList` in `MtlsAuthenticator` at both ports, reload ≤ 30 s; rustls `with_crls` for REST; both session registries drop revoked | **opt-in**: a fleet that does not set `auth.crl` revokes nothing (see §14) | `checks.vm-keys-revoke` (126 s), V24 |
| A rollback does not revive a revoked identity | the CRL is not part of a system generation | — | part of `vm-keys-revoke` |
| Two machines from one image are two machines | machine-id and host keys are generated on first boot | — | `checks.vm-two-instances-same-image` (47 s), V08/L04 |
| An interrupted run can be resumed | append-only journal with fsync per line; `action.irreversible` before the point of no return; resume reads the journal **and** the target | a lost journal **and** a missing transaction record is `recovery-required`, by hand | V17 table; `kill -9` in the lab (L09) and in `vm-keys-revoke` |
| Nothing is built out of a developer's home directory | everything is a Nix package; the build runs in the sandbox | — | `checks.no-developer-home`, `checks.managed-uses-the-package` |
| A verification only deletes what it created | ledger written *before* the create; tag `meister-verify-<run_id>` | leftovers after an abort are reported, not hidden | real run on manacor: 3 guests in 161 s, ledger empty afterwards, a foreign guest untouched |

**Not guaranteed, and said here rather than found out later:**

* bit-identical rebuilds — `reproducibility.bit_identical_verified` is only
  true after an actual `nix build --rebuild` comparison (`--verify-reproducible`);
* anything about a host that did not answer — that is `unknown`, and a
  required `unknown` blocks;
* that a `check` which passes means the workload works — that is `verify`;
* GPU and RDMA on real hardware unless a run says `kind=hardware` (see §19).

---

## 3. Create the operator repository

Your fleet is **your** repository. This one builds no fleet of its own.

```
meister-deploy init ~/fleet --meisterstack git+file:///home/silas/git/MeisterStack?ref=main
cd ~/fleet
nix-store --generate-binary-cache-key fleet keys/signing.sec signing.pub
git init && git add -A
```

Three things about those four lines:

1. **`--meisterstack` is not optional in practice.** Without it, `init`
   writes the `github:UniStuttgart-IKR/MeisterStack/<rev>` pin it was built
   with, and that revision's flake has no `disko` input — `nix flake lock`
   then fails with *"input 'disko' follows a non-existent input
   'meisterstack/disko'"*. Measured today. Point it at the checkout or at a
   revision that has the input.
2. **The signing key is step 1, not step 5.** A managed host runs with
   `require-sigs = true` and refuses an unsigned closure even from root
   (measured, M0 probe S12). `meisterstack.managed.trustedPublicKeys` is a
   required option and its assertion fires at evaluation, so a fleet without
   a key does not build. `keys/` is created by `init`; `keys/` is in the
   generated `.gitignore` and `signing.pub` is not.
3. **A flake sees only what git tracks.** An untracked file is invisible to
   `nix build` and `resolve` refuses a dirty tree by name (it lists the
   files). So: `git add -A` before every build, and see §7.

What `init` writes: `flake.nix`, `fleet.toml`, `profiles.nix`,
`profiles/{base,controller,compute-cpu,compute-gpu-pro6000,observability-local}.nix`,
`hosts/<id>.nix`, `disko/{single-nvme,single-direct}.nix`, `known_hosts`
(empty, committed), `tests/default.nix`, `.gitignore`, `.meister-deploy/`,
`keys/`. It refuses a directory that is not empty and it never touches a
MeisterStack checkout (V01; `tests/cli_init.rs`, `tests/template_files.rs`).

---

## 4. Assign profiles and hosts

`fleet.toml` is schema 2. Precedence is `defaults < group < host`; two groups
of equal rank that disagree about the same key are an error that names both
groups. Nix derives every deployment value from this file and Rust only reads
its shape — `checks.inventory-parity` compares the two readers.

```toml
schema = 2

[fleet]      name = "uni-lab"   domain = "lab"
[defaults]   ssh = { user = "root", port = 22 }
             profiles = ["base"]
             rollout = { max_unavailable = 1, reboot = "approve" }
             checks  = { required = ["units", "session", "mounts"] }
[operator]   cli_config = "/home/silas/fleet/cli.toml"   # absolute, see below
             cli_profile = "cloud-mtls"
             ca_dir = "../labpki"
             signing_key = "keys/signing.sec"

[[group]]  id = "cloud"      kind = "raft"     profiles = ["controller"]
[[group]]  id = "compute"    kind = "compute"  profiles = ["compute-cpu"]

[[host]]
id = "cloud-a"  name = "meister-cloud"  deployment = "nixos"  boot = "uefi"
roles = ["cloud", "cluster"]  groups = ["cloud"]
networks.management = { address = "10.128.1.103", prefix = 24, interface = "eno1" }
install = { disk = { serial = "S6PENX0T123456", size_gb = 960 }, layout = "disko/single-nvme.nix" }
persistence = [{ path = "/var/lib/meister-data", device = "label:meister-data", required = true }]
modules = ["hosts/cloud-a.nix"]
```

Five things that cost an afternoon each in the lab:

* **`[operator] cli_config` must be an ABSOLUTE path.** It is resolved
  against the current working directory, so a relative one works from the
  repository root and breaks from anywhere else (finding P2, lane 4B).
* **`prefix` is the real prefix length of the management network.** A wrong
  one does not matter to a context VM and is fatal to the first managed host
  on the same wire (lab finding, L2 §11).
* **Firewall ports belong to your host module, not to these modules.** The
  service modules publish the numbers (`config.meisterstack.ports`) and open
  nothing — opening a port is host-global, and `checks.services-are-pure`
  holds the modules to that. What a control plane needs:
  `networking.firewall.allowedTCPPorts = with config.meisterstack.ports; [ cloud.api cloud.grpc cluster.api cluster.grpc etcd.peer ];`
  The 5A VM test hung on exactly this.
* **The disk must be at least four times the closure.** A managed host holds
  the running closure and the next one, plus the store's own overhead; the
  lab's first managed VM had 1.8 GiB free for a 1.3 GiB closure and could not
  stage anything (L2 §10.2).
* **`boot = "uefi" | "direct"`.** `uefi` is a machine that boots itself and
  has the boot-mode rollback. `direct` is a guest whose hypervisor loads the
  kernel — no boot loader, no boot-mode rollback, and a kernel change becomes
  a `provider-reboot` (§12). `bios` is refused with a sentence: a grub host
  has no `bootctl set-oneshot`, so the fleet cannot promise it a way back.

---

## 5. Update inputs

```
nix flake update meisterstack        # or: nix flake update nixpkgs
git add flake.lock && git commit
```

`flake.lock` travels into the manifest (`source.flake_lock`: url, rev,
nar_hash per input), so a release says which inputs it was built from. An
update that changes the kernel is a reboot class, and §11 says what that
means.

---

## 6. Check the manifest

```
meister-deploy validate -f fleet.toml          # shape and precedence, offline
meister-deploy inventory --json                # what each host inherited
meister-deploy resolve --repo . --out manifest.json
```

`resolve` calls `nix eval --json .#meisterDeployment`: one evaluation, no
module evaluation per host unless it is needed. It **refuses a dirty tree**
and names the untracked files. `--dev` resolves one anyway, but then it
materialises a content snapshot (exactly the scanned file set, secret-scanned)
and records `dirty: true` — a `dev:` fingerprint is never a `git:` one.

* `--hosts a,b,c` evaluates a sub-fleet and records `evaluated_hosts`. On 70
  hosts a full `resolve` was measured at **~21 minutes** (extrapolated from
  20 hosts, lane 4C) and `nix eval` is the whole of it — `--hosts` is the
  lever, not parallelism.
* **Do not put `resolve` in a pipeline with `tail`.** `resolve … | tail -3 &&
  build …` tests the pipe, not the tool: in the lab that ran `build` on an
  *old* manifest although `resolve` had correctly refused the dirty tree
  (L2 §10.6). Write the commands on separate lines.
* `validate --manifest manifest.json` checks a contract file against the
  types. `checks.manifest-json` does the same thing inside `nix flake check`.

---

## 7. Build and sign

```
meister-deploy build --manifest manifest.json --sign-key keys/signing.sec \
    --out release.json
```

One `nix build` for the whole fleet (lane 4C), then `nix path-info --json`
for every output, then `nix store sign`. The release embeds the manifest
unchanged, so the source fingerprint cannot drift from the artifacts.
Garbage-collector roots are placed under `.meister-deploy/gcroots/<release_id>/`
— a release you may still roll back to is a release whose closure is still
there.

* **A cache is optional and it is a push, not a pull:** `build --cache
  file:///srv/cache` runs `nix copy --to file://…`. A host only fetches from
  a cache it names (`[[host]] managed.substituters`), and a fetched path is
  held to `require-sigs = true` exactly like a pushed one.
* 70 hosts: **~3 minutes** for `build` once the store is warm, **1.59 GiB**
  of store added (lane 4C, extrapolated from 20).
* `--verify-reproducible` runs `nix build --rebuild` and compares. Only then
  does `reproducibility.bit_identical_verified` become true.
* Retention: `meister-deploy gc --keep 3 --older-than 14` is the recommended
  pair (lane 4C). It drops roots; whether a path actually goes is
  `nix store gc`'s decision. `--observations N` and `--runs` trim the other
  two things that pile up.

---

## 8. Install a new host

```
meister-deploy plan --release release.json --select host=cloud-a --kind install \
    --out install-plan.json
meister-deploy install --plan install-plan.json --release release.json \
    --host cloud-a --approve destructive=<plan_id>
```

`install` builds the medium and prints the sheet somebody carries to the
machine: host id, disk serial, size, what will be preserved, and the plan id.
It destroys nothing — the disk is formatted at the target, by a person:

```
# on the machine, booted from the medium:
meister-install confirm --host cloud-a --disk S6PENX0T123456 --plan <plan_id>
```

It resolves the serial through `lsblk -J`, insists that it is unique (two
disks with one serial is an abort), shows host/disk/size/scope, then runs
`disko` + `nixos-install --system <toplevel> --no-root-passwd`, generates the
SSH host key under `/mnt/etc/ssh` and **prints the fingerprint**. That
fingerprint is the one you type in §9; write it down from the console.

* The medium carries no secret: `checks.installer-no-secrets` walks the
  embedded closure for key-shaped names and greps the shipped `/etc` for
  `PRIVATE KEY`; the complete form over the mounted ISO runs inside
  `vm-install-blank-disk`.
* A second boot of the same medium does **not** format again — the
  installation marker `/etc/meister-install/installed.json` is why — until
  somebody says `--reinstall` (V07).
* **`boot = "direct"`:** there is no ISO. `meister-deploy image --release
  release.json --host <id> --kind direct-boot` writes a bundle of three files
  (`kernel`, `initrd`, `cmdline`); your provider adapter loads them. Measured
  in `checks.vm-install-direct-boot` (107 s).
* **nixos-anywhere** is a documented alternative for a machine that already
  runs some Linux with SSH: it kexecs an installer and uses the same disko
  layout. It does not check a disk serial, leaves no installation marker, and
  needs a host you already trust. `deploy/README.md` has the longer comparison.

---

## 9. Enrol

```
meister-deploy keys enroll cloud-a --fingerprint SHA256:… --repo . -f fleet.toml
```

The fingerprint comes from the machine's console, its BMC or the installer's
last line — **never** from this command. `ssh-keyscan` reports whatever
answers on the address; believing it would make an impersonating host
self-certifying. The verb scans, compares with what you typed, and writes
`<repo>/known_hosts` only if they match. A different existing key is refused
unless you say `--replace --reason <why>`, and the reason lands in the file
above the new line.

**If your provider has no console channel**, say so out loud. The lab has no
OneGate, so L2 used a provider scan and *labelled it as one* in the output,
the journal and the report. A runbook may not offer that as a normal path:
an unverified fingerprint is an unverified fingerprint.

Then the service identity:

```
meister-deploy keys csr --host cloud-a --kind identity --as cloud --manifest manifest.json
meister-deploy keys issue --host cloud-a --kind cloud --manifest manifest.json
git add pki/ && git commit -m "cloud-a: request and certificate"
```

`keys csr` makes the key **on the host** and brings back only the request.
`keys issue` signs it here; the CA key never leaves this machine. A host with
two tiers has one `identity.key` and therefore one identity — `--as` says
which, and without it the tool lists the candidates rather than guessing.

**Commit the CSRs and certificates before you build again.** They are public,
they live in the repository, and `resolve` refuses a dirty tree — in the lab
this is the step people forget and then wonder why `resolve` says no
(L2 §10.7).

**Certificates a CA already issued** (a fleet older than this tool) come in
with:

```
meister-deploy keys import --from ~/labpki \
    --map cloud-a=system-cloud-meister --map n1=system-node-n1 \
    --manifest manifest.json --inventory fleet.toml
```

It reads the subject off each file and refuses a mapping whose CN is not the
one this fleet would have issued for that host. The private key is looked at
and nothing else: if it lies beside the certificate it must be mode 0600, and
it is never read or copied — it stays on the machine it belongs to. The
certificates land under `pki/issued/<host>/`, `ca.crt` goes into the CA
directory if it has none, and `meister-ca --index-rebuild` runs so that an
imported certificate can also be taken back later. Verified against a real
throwaway CA in `tests/cli_import.rs`.

---

## 10. Bootstrap

A fleet that is not running yet: the controllers come up before the nodes
that dial them, and the identities are delivered before anything is
activated.

```
meister-deploy plan --release release.json --select all --kind bootstrap \
    --inventory fleet.toml --repo . --out bootstrap.json
meister-deploy apply --plan bootstrap.json --release release.json \
    --approve singleton=<plan_id>
meister-deploy check --release release.json --inventory fleet.toml
```

`check` exits 0 when every required check passed and **2** when one did not.
Exit 2 is not a failure of the tool — it is the fleet saying no.

This whole sequence is `checks.vm-bootstrap-fleet` (**437 s**): two empty
virtual disks → installer → enrolment from the console → CSR → bootstrap →
`check` → update → kernel change with a provider halt and a resume. It also
ran in the lab against two fresh OpenNebula VMs (L2: `check` 9/0 on the
controller, 8/0 on the agent) — on the fourth attempt, and the three failures
were real tool bugs that are fixed.

---

## 11. Update

```
meister-deploy resolve --repo . --out manifest.json
meister-deploy build --manifest manifest.json --sign-key keys/signing.sec --out release.json
meister-deploy plan --release release.json --select all --inventory fleet.toml --repo . --out plan.json
meister-deploy apply --plan plan.json --release release.json
```

Read the plan before you apply it. It names, per host: the current and the
desired system, whether a reboot is needed and why, which approval class it
belongs to, what it waits for, and what it would do to the workload.

**Approvals** are per class and bound to the plan:
`--approve reboot=<plan_id>`, `disruptive=`, `singleton=`, `destructive=`,
`quorum=`. There is no global `--force`, and an approval for one plan does
not carry to another. `verify` is the one exception: it rolls nothing out,
so its approval names the release (`--approve verify=<release_id>`). `apply` without a needed approval is exit 2
with the sentence that says which class.

**What `apply` does per host** (§6 of the design; `execute.rs`): preflight →
lock → stage (`nix copy --to ssh-ng://`, then `nix path-info` on the target to
check the NAR hash) → cordon/drain if the step interrupts an agent →
`action.irreversible` in the journal → activate → reboot if the class says so
→ verify → confirm → uncordon → unlock. A reapply of an unchanged fleet
writes an `unchanged` receipt and touches nothing (V10, measured in
`vm-managed-update` and in the lab).

**Workload protection** needs `[operator] cli_config`/`cli_profile`. Without
it, steps that would interrupt an agent are `blocked` with a sentence — there
is no fallback, because draining a node you cannot talk to is not draining it.

**`check` is not a small `plan`.** `check --release` does not read
`[operator]` unless you pass `--inventory`, so a green `check` after a
bootstrap has said nothing about workload protection (L2 §10.14). Pass
`--inventory fleet.toml` to `status` and `check` as well; it is also what
lets them tell a retired host from a live one (§15).

**One full line per verb.** The flags differ and they are not guessable:
`check` takes `--inventory` but not `-f`; `plan` insists on `--select`;
`keys csr` wants `--manifest`, not `-f`. Copy the lines from this file rather
than remembering them (L2 §10.4).

**70 hosts, measured (lane 4A):** `plan` 14 ms, 140 reading commands, 15
waves. Serial execution at ~30 s per host is 25–35 minutes; `--parallel` was
deliberately **not** built, because the number that decides whether it is
worth it (a real reboot on real hardware) has not been measured.

---

## 12. Provider reboot (direct-boot hosts)

A host with `boot = "direct"` has no boot menu: its kernel, initrd and command
line come from outside. When a release changes any of the three, `apply`
stops in front of it with **exit 2** and a JSON line naming the bundle:

```
{"action":"provider-reboot","host":"n1",
 "kernel":"/nix/store/…/bzImage","initrd":"/nix/store/…/initrd",
 "cmdline":"… init=/nix/store/…-nixos-system-n1-25.11/init"}
```

Your provider adapter loads those three and restarts the machine; then:

```
meister-deploy apply --plan plan.json --release release.json --resume <run-id>
```

which checks `booted_system == desired` and carries on. There is no hidden
reboot and no bundle upload by this tool. Measured in
`checks.vm-bootstrap-fleet` and, against real OpenNebula, in L2 §6.

**What is not verified:** a real OpenNebula direct boot end to end. ONE's
`updateconf` keeps only `KERNEL_CMD`, so the kernel has to be named at
`allocate` time — which means a new VM. L2 says so and stops there.

---

## 13. Verify workloads

`check` reads. `verify` makes the fleet do its job:

```
meister-deploy verify --release release.json --suite vm-lifecycle \
    --approve verify=<release_id> --budget 3 --deadline 600
```

It writes a ledger **before** it creates anything, tags everything
`meister-verify-<run_id>`, creates guests through *your* control plane
(`[operator] cli_config`), reads what they printed, and deletes only what it
made. On an abort it reports what is left rather than tidying silently, and a
successful cleanup never makes a failed test green.

Measured on manacor against a throwaway control plane: **3 guests in 161 s**,
ledger empty afterwards, a foreign guest untouched, evidence `MS-S0-TINY-OK`
with `kind=hardware`.

Two things a run through the CLI needs and no single error message lists
together (L2 §10.10–12): `meister vm create` wants a spec without
`apiVersion`/`kind`, at least one volume, a `base_image` registered with
`meister image create`, and a `--tenant`; `meister vm rm` refuses without a
tty and wants `--yes`; `node ls` prints `READY Unprivileged` without the
reason — the reason is in `-o json` under `conditions[].message`.

Suites `gpu` and `rdma` are `not_applicable` on a host that declares no such
hardware, and `skipped` when it declares some and cannot be reached — a
required `skipped` blocks (V22). A CPU mock is never `kind=hardware`.

---

## 14. Rotate and revoke

**Revocation is opt-in, and that belongs in the first sentence.** A fleet
switches it on by naming `auth.crl` for its controller roles and putting an
empty list in the repository *before* the first bootstrap:

```toml
deviations.settings.cloud   = { auth = { crl = "/var/lib/meisterstack/pki/crl.pem" } }
deviations.settings.cluster = { auth = { crl = "/var/lib/meisterstack/pki/crl.pem" } }
```

```
meister-ca --dir <ca_dir> --index-rebuild --gencrl
cp <ca_dir>/crl.pem pki/crl.pem && git add pki/crl.pem
```

A controller that names a list it has not got does not start. That is
deliberate — a revocation check that silently does nothing is worse than
none — and it is why the list has to exist first. The derivation does not
render `auth.crl` by itself (lane 5A): doing so would have killed every
context VM at once.

Taking one back:

```
meister-deploy keys revoke --host n1 --reason keyCompromise \
    --release release.json --inventory fleet.toml --out revoke.json
meister-deploy apply --plan revoke.json --release release.json     # no approval needed
```

The list takes effect **without restarting anything**: a controller re-reads
the file within 30 seconds, refuses the serials on it, and ends sessions that
are already running on one. A rollback does not revive a revoked identity,
because the list is not part of a system generation. All of that is
`checks.vm-keys-revoke` (126 s, V24).

**The list expires after 30 days.** `meister-deploy keys revoke --refresh`
writes it again. Nothing reminds you — put it in a calendar.

Replacing a key:

```
meister-deploy keys rotate --host cloud-a --kind identity --as cloud \
    --release release.json --inventory fleet.toml --out rotate.json
meister-deploy apply --plan rotate.json --release release.json --approve disruptive=<plan_id>
```

Five phases — prepare, overlap, switch, verify, remove — and `apply` may be
interrupted after any of them; `--resume <run-id>` picks up at the phase the
host is actually at, without a second `prepare` (measured with `kill -9`
during `overlap`). After a rotation these belong in a commit:
`pki/csr/<host>-<kind>.next.csr`, `pki/issued/<host>/<kind>.crt`,
`pki/issued/<host>/<kind>.prev.crt` (still valid until somebody takes it
back) and `pki/crl.pem`.

---

## 15. Retire

```
meister-deploy retire n1 --release release.json --inventory fleet.toml \
    --reason "decommissioned" --out retire-plan.json
meister-deploy apply --plan retire-plan.json --release release.json
```

In that order, `retire` does three things and no more:

1. takes back every certificate this repository holds for the host and
   publishes a new list into `pki/crl.pem`;
2. writes `.meister-deploy/retired/<host>.json` (day, reason, the serials, the
   system it was last seen running) and puts a `# retired <date> <reason>`
   line **above** the host's `known_hosts` entry — the entry stays, so a
   machine that later answers on that address collides with it instead of
   being enrolled quietly;
3. plans the delivery of the new list to **the rest of the fleet**
   (`all,!host=n1`). The host being retired is not in its own plan: it may be
   off, broken or already gone, and a verb that needed its answer could not
   retire the host you most want rid of.

**Nothing is deleted.** Not a partition, not a data directory, not the
certificate files on the machine, not the `known_hosts` line, and not the
lines in `fleet.toml`. Removing the host from the inventory is your edit —
the tool never rewrites an inventory, because an inventory a tool rewrites is
one whose diff says nothing.

Until you make that edit, `status --inventory fleet.toml` shows the host as
`unmanaged` and says whether `retire` ever ran for it:

```
    n1             unmanaged -         -  0 pass, 0 fail, 0 unknown    -
    note     managed on n1: n1 is not in the inventory any more; `retire` was
             2026-09-23 (decommissioned). …
```

An `unmanaged` host is not asked anything and blocks nothing. A `[[service]]`
with `managed = false` that does not answer is `unknown`, and that blocks only
where the inventory says `required = true`. Both halves are V25
(`tests/cli_look.rs`, `plan.rs`).

---

## 16. Resume an interrupted run

```
meister-deploy report --run <run-id>          # what happened so far
meister-deploy apply --plan plan.json --release release.json --resume <run-id>
```

The journal is append-only with an fsync per line, and `action.irreversible`
is written *before* the step that cannot be taken back — so a resume knows
what it must not repeat. It then asks the target: the transaction record on
the host says `confirmed` or `reverted`, and that is what decides the host's
outcome, not the journal alone.

**A failed run leaves exactly three things, in three places** (L2 §10.8), and
this is the way out of each:

| What | Where | How it goes |
|---|---|---|
| the operator lock | `<repo>/.meister-deploy/lock` | `apply --takeover <run-id>` (re-observes) or delete it once you are sure no other run is alive |
| a lock on a host | `/var/lib/meisterstack/deploy/lock/` on the target | `meister-activate lock release` on the host, or the takeover above |
| an open transaction | `/var/lib/meisterstack/deploy/txn/<id>.json` | `meister-activate txn show <id>`, then `confirm` or `revert` |

A host whose transaction record is missing or inconsistent is
`recovery-required`, and that state is deliberately manual: `meister-activate
txn list` and `txn show` on the host tell you which generation it is on, and
`meister-activate revert` puts it back. (Lane 5C is adding `txn retire
--force` for the inconsistent case; until that is merged this is by hand.)

**Never release a lock by waiting.** Locks in this tool are never released by
a timeout — a lock whose owner is dead is still a statement that a run got
that far.

---

## 17. Emergency access

At 03:00, on the machine, without this tool:

```
meister-activate status --json        # current / booted / next-boot, generation, open txns, lock
meister-activate txn list
meister-activate revert --txn <id>    # back to the previous system (the id: `txn list`)
meister-activate confirm --txn <id>   # keep the current one, cancel the revert timer
meister-activate lock show
meister-activate lock release --run <run-id>   # the run id is in `lock show`
meister-activate gc --keep 3
nixos-rebuild switch --flake /path/to/fleet#<host>     # the blunt instrument
```

`meister-activate` is part of every managed host's closure, so it is there
whatever else is broken. After a manual change, run `meister-deploy status
--release release.json` from the workstation: the host will show a system that no release names, and
that is what the drift looks like. The next `plan` will offer to put it back.

`nixos-rebuild --target-host` from the workstation also still works and is
the documented emergency path. It writes no journal and no receipt — that is
the trade, and `status` is where the difference shows up.

---

## 18. Migrating the context fleet

The lab's twelve OpenNebula VMs boot a generic image and render their
configuration at boot from a CONTEXT medium. Since M5B none of that is in this
repository: the image, the renderer, `push.sh`, `check.sh`, the template and
`lab.toml` live in `~/git/meisterstack-lab/legacy/`, with their own render
test (140 checks) and a parity proof that the image there is the *same
derivation* (72 units, each the same store path). `deployment = "context"` is
still a valid value here; a plan refuses such a host by name and points at
that push.

What stayed is `nixosModules.provider-opennebula`: READING the medium a
hypervisor handed a guest is not the same thing as rendering configuration
at boot, and a managed host can want the first without the second — it was
instantiated on OpenNebula and gets its address from there. It parses
`context.sh` with a `KEY='value'` grammar and an allowlist of six keys
(ETH0_IP/MASK/GATEWAY/DNS, SET_HOSTNAME, SSH_PUBLIC_KEY), never sources it,
and takes no `MEISTER_*` off the medium: what a machine IS comes from the
inventory.

The way over, per VM (§8a of the design; **needs the lab, so it needs Silas'
word**):

1. reconcile `fleet.toml` against reality first — `lab.py survey --deep`. In
   the lab the names and one address were wrong, and `name` is what becomes
   `SET_HOSTNAME` and the node id (L2 §11.1);
2. build `packages.managed-disk-image` and register it as an image;
3. start a **fresh** VM from it (never re-image one of the twelve), with a
   disk at least 4× the closure and the old data block attached by image id;
4. `keys enroll` with the fingerprint from the console, `keys csr`,
   `keys issue`;
5. `plan --kind bootstrap` → `apply` → `check`;
6. only then terminate the old VM.

Certificates and data do not get regenerated to make something green: the old
certificates come in with `keys import` (§9), and the data block is carried
over by label, declared in `persistence[]` and protected by
`install.preserve`.

**What is still open for that migration** (measured and listed, not guessed):
`prefix = 24` is wrong in the inventory; every one of the twelve has a second
NIC that `networks.management` cannot describe; every one has a second disk
that has to be attached by image id; and three tool findings (N4 grub as an
inventory value, N5 a provider parser for managed hosts, N6 resolvconf on
managed) are preconditions. Without N4 every migrated VM has to be `direct`.

---

## 19. Limits

* **grub**: no boot-mode rollback. A grub host keeps its boot loader through
  its own host module; the fleet does not install one, because `bootctl
  set-oneshot` is what makes a failed boot survivable and grub has no
  equivalent here. Switch-mode rollback works unchanged.
* **BIOS/MBR**: not installed by this flake. `boot = "bios"` is refused with a
  sentence rather than half-supported.
* **GPU**: the `gpu` suite exists and was run once on manacor, where it
  measured `not_applicable` (no `[device.*]`, no vfio). It has **not** been
  run against the RTX 2070 with `nvrm` — that needs Silas' word each time, and
  the report of lane 4B says so rather than implying a green.
* **RDMA**: the suite exists (rping / ib_send_lat / ib_write_bw between
  declared peers) and has no hardware to run on here. It reports
  `not_applicable` with the reason.
* **Parallelism**: one host at a time within a wave. `--parallel` was not
  built; the threshold that would justify it is 103 s per host and the real
  number (a reboot on metal) has never been measured.
* **70 hosts**: `plan` 14 ms, `build` ~3 min, `resolve` **~21 min** — the
  evaluation is the bottleneck and `--hosts` is the answer. Both figures are
  extrapolated from a measured 20-host fleet (lane 4C), not run at 70.
* **Bit-identical rebuilds** are only claimed after `--verify-reproducible`.
* **`nix flake check`** builds ten NixOS VM tests and takes about an hour on a
  quiet machine (3220 s at gate M3, 3524 s at gate M4). Under memory pressure
  the linker has been seen to die; run it alone.
* **This tool has never run against 70 real machines.** Everything above was
  measured in VMs, in the lab against two fresh OpenNebula VMs, or on this
  workstation. Where a number is extrapolated, it says so.

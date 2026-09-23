// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The fourth contract, and the one decision in this tool that is pure.
//!
//! A [`DeploymentPlan`] is the answer to one question: given what was built
//! ([`crate::release::ReleaseManifest`]) and what is there right now
//! ([`crate::observation::Observations`]), what may happen, to which host,
//! in which order, and what has to still be true when it does. Nothing in
//! this module reaches outside the process — no ssh, no nix, no file, no
//! clock. `now` arrives as a value.
//!
//! That is not tidiness. Every safety rule of a rollout lives here — the
//! quorum arithmetic, the reboot class, the identity check, the frozen
//! target set — and a rule that can only be exercised against a fleet is a
//! rule nobody exercises. This way each of them is a table and a test, the
//! way [`meister_controller_api::drain`] made the drain table one.
//!
//! Three properties the tests hold this to:
//!
//! * **The selection is frozen.** `selection.targets` is computed once and
//!   written down. A label added to a host afterwards does not add the host
//!   to a plan that was already made.
//! * **Nothing is derived twice.** The desired system is
//!   `release.artifacts.<h>.toplevel.store_path` and never anything this
//!   module computed from a fleet.
//! * **A missing fact is never a pass.** An unreadable kernel, an absent
//!   etcd answer, a host nobody reached: each of them blocks, and each of
//!   them says which fact was missing.
//!
//! [`meister_controller_api::drain`]: ../../../meister_controller_api/drain/index.html

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ids::{IdKind, content_id};
use crate::manifest::{GroupKind, ResolvedFleet};
use crate::observation::{Endpoint, Observations, Targets};
use crate::release::ReleaseManifest;

pub const PLAN_SCHEMA: &str = "meister-deploy/plan/1";

// ---------------------------------------------------------------------------
// What kind of plan this is
// ---------------------------------------------------------------------------

/// What a plan is FOR. The kind changes the order of the actions and which
/// of them exist at all, so it is a field of the plan and not a flag of the
/// run: `bootstrap` puts the prerequisite before the dependant and delivers
/// secrets before it activates anything, `upgrade` does the opposite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum PlanKind {
    /// A fleet that is not running yet: identities are delivered, and a node
    /// is brought up after the thing it talks to.
    Bootstrap,
    /// A fleet that is running: a node is taken forward BEFORE the node that
    /// gives it orders.
    Upgrade,
    /// First installation from a medium. M3.
    Install,
    /// M5.
    KeysRotate,
    /// M5.
    KeysRevoke,
    /// M5.
    Retire,
}

impl PlanKind {
    pub fn as_str(self) -> &'static str {
        match self {
            PlanKind::Bootstrap => "bootstrap",
            PlanKind::Upgrade => "upgrade",
            PlanKind::Install => "install",
            PlanKind::KeysRotate => "keys-rotate",
            PlanKind::KeysRevoke => "keys-revoke",
            PlanKind::Retire => "retire",
        }
    }
}

impl std::fmt::Display for PlanKind {
    /// `pad` and not `write_str`: the second one writes straight to the sink
    /// and ignores the width a caller asked for, so `{:<12}` on one of these
    /// would silently print an unpadded column.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

/// One step against one host.
///
/// `lock` and `unlock` are steps like any other rather than something the
/// executor does around them: a lock that is not in the plan is a lock
/// nobody can see in a receipt, and D6 makes the lock the thing that keeps
/// two operators apart.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum ActionKind {
    Preflight,
    Lock,
    Stage,
    DeliverSecret,
    Cordon,
    Drain,
    Activate,
    Reboot,
    // --- lane 3-integration: the boot nobody inside the machine owns ------
    /// The machine has to come up on a kernel its PROVIDER loads.
    ///
    /// A `boot = "direct"` host carries no boot loader (3A): its hypervisor
    /// is handed a kernel, an initrd and a command line, and what the guest
    /// says about its next boot is a statement about its system profile and
    /// not about what will actually start. So a reboot that has to take a
    /// new kernel cannot be `systemctl reboot` — the machine would come back
    /// on the bytes the provider loaded last time, which are the old ones.
    ///
    /// `apply` does not carry this step out. It stops at it, with the bundle
    /// and with exit 2; whoever arranges the provider does the loading and
    /// the reboot, and comes back with `apply --resume <run-id>`.
    ProviderReboot,
    // --- end lane 3-integration -------------------------------------------
    Verify,
    Confirm,
    Uncordon,
    Unlock,
    Install,
    Revoke,
    Gc,
    // --- lane 5A: the five phases of a rotation ---------------------------
    //
    // Five steps and not one, because each of them is a point a run can be
    // interrupted at and picked up from — and because only one of them
    // interrupts anything. A rotation that were a single action would be a
    // rotation whose failure left a machine holding half a pair.
    /// The new key is made on the host, beside the one in use.
    KeysPrepare,
    /// The certificate for it is put there, beside the one in use. Nothing
    /// reads either of them yet.
    KeysOverlap,
    /// The prepared pair becomes the pair in use, and the units that read it
    /// are restarted. The one step of a rotation that interrupts anything.
    KeysSwitch,
    /// The host says what it now holds, and a session says it works.
    KeysVerify,
    /// What the switch replaced goes away.
    KeysRemove,
    // --- end lane 5A ------------------------------------------------------
}

impl ActionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ActionKind::Preflight => "preflight",
            ActionKind::Lock => "lock",
            ActionKind::Stage => "stage",
            ActionKind::DeliverSecret => "deliver-secret",
            ActionKind::Cordon => "cordon",
            ActionKind::Drain => "drain",
            ActionKind::Activate => "activate",
            ActionKind::Reboot => "reboot",
            ActionKind::ProviderReboot => "provider-reboot",
            ActionKind::Verify => "verify",
            ActionKind::Confirm => "confirm",
            ActionKind::Uncordon => "uncordon",
            ActionKind::Unlock => "unlock",
            ActionKind::Install => "install",
            ActionKind::Revoke => "revoke",
            ActionKind::Gc => "gc",
            // --- lane 5A ---
            ActionKind::KeysPrepare => "keys-prepare",
            ActionKind::KeysOverlap => "keys-overlap",
            ActionKind::KeysSwitch => "keys-switch",
            ActionKind::KeysVerify => "keys-verify",
            ActionKind::KeysRemove => "keys-remove",
            // --- end lane 5A ---
        }
    }

    // --- lane 5A ---
    /// Is this one of the five steps of a rotation?
    pub fn is_keys(self) -> bool {
        matches!(
            self,
            ActionKind::KeysPrepare
                | ActionKind::KeysOverlap
                | ActionKind::KeysSwitch
                | ActionKind::KeysVerify
                | ActionKind::KeysRemove
        )
    }
    // --- end lane 5A ---

    /// Whether this step, once begun, cannot be taken back by this tool.
    /// The journal writes `action.irreversible` before exactly these, and a
    /// resume never repeats one blind (V17).
    ///
    /// `provider-reboot` is not one of them, and that is the point of it:
    /// this tool never starts it, so there is nothing it could half-do. What
    /// it writes is a halt, and asking the machine again whether it has
    /// booted the desired system is a question, not a repetition.
    pub fn is_irreversible(self) -> bool {
        matches!(
            self,
            ActionKind::Activate | ActionKind::Install | ActionKind::Revoke
        )
    }
}

impl std::fmt::Display for ActionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad(self.as_str())
    }
}

/// What a step does to what is running on the host.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Disruption {
    /// Nothing that is running stops.
    None,
    /// A unit restarts; guests on the host survive.
    Service,
    /// The machine goes away for a while.
    Reboot,
}

/// Which question an operator has to have answered before a step may run.
///
/// One class per action, because that is what `--approve <class>=<plan_id>`
/// grants. Where a step would need two — the only cloud controller, and it
/// also needs a reboot — the action carries the HARDEST one and the plan's
/// `approvals` carries both: the grant list is the gate, and it is the
/// union. So approving `singleton` never quietly buys a reboot.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalClass {
    /// Nobody has to be asked.
    None,
    /// Something that is running will be interrupted.
    Disruptive,
    /// A raft group of one: there is no quorum to keep, and the service is
    /// gone while this runs.
    Quorum,
    /// The machine reboots.
    Reboot,
    /// The only member. Whatever it serves is unavailable, full stop.
    Singleton,
    /// Data is destroyed: a disk is partitioned, a certificate is revoked.
    Destructive,
}

impl ApprovalClass {
    pub fn as_str(self) -> &'static str {
        match self {
            ApprovalClass::None => "none",
            ApprovalClass::Disruptive => "disruptive",
            ApprovalClass::Quorum => "quorum",
            ApprovalClass::Reboot => "reboot",
            ApprovalClass::Singleton => "singleton",
            ApprovalClass::Destructive => "destructive",
        }
    }
}

impl ApprovalClass {
    /// The other direction, for `--approve <class>=<plan_id>`. An unknown
    /// word lists the ones that exist rather than silently granting nothing.
    pub fn parse(text: &str) -> Result<ApprovalClass> {
        match text {
            "none" => Ok(ApprovalClass::None),
            "disruptive" => Ok(ApprovalClass::Disruptive),
            "quorum" => Ok(ApprovalClass::Quorum),
            "reboot" => Ok(ApprovalClass::Reboot),
            "singleton" => Ok(ApprovalClass::Singleton),
            "destructive" => Ok(ApprovalClass::Destructive),
            other => bail!(
                "{other:?} is not an approval class. This tool knows: disruptive, quorum, \
                 reboot, singleton, destructive."
            ),
        }
    }
}

impl std::fmt::Display for ApprovalClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RollbackMode {
    /// Nothing to take back.
    None,
    /// The target switches back to the previous system when nobody confirms.
    Switch,
    /// The target boots the previous system once when nobody confirms. Only
    /// possible with systemd-boot (`bootctl set-oneshot`); a grub host gets
    /// `switch` and the documented limit.
    Boot,
}

/// How a step takes itself back, and how long the target waits for a word.
///
/// The mode is also the mode the activation RUNS in
/// (`meister-activate --mode switch|boot`): a boot activation is taken back
/// by a boot entry and a switch activation by a switch, so the two are one
/// decision and one field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Rollback {
    pub mode: RollbackMode,
    /// How long the target waits for `confirm` before it reverts. Zero when
    /// there is nothing to revert.
    pub confirm_within_secs: u64,
}

impl Rollback {
    pub fn none() -> Rollback {
        Rollback {
            mode: RollbackMode::None,
            confirm_within_secs: 0,
        }
    }
}

/// Why this step waits for another host.
///
/// The reason travels with the edge because an order nobody can explain is
/// an order nobody dares change. "cluster-1 gives orders to this agent" is
/// checkable against the inventory; "clusters come after agents" is folklore.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Dependency {
    pub host: String,
    pub reason: String,
}

/// One fact that has to still be true when the step actually runs.
///
/// Separate from `preconditions`, which are the sentences the planner
/// checked when it planned. These are re-evaluated by
/// [`validate_against`] immediately before every mutation, which is the
/// difference between "it was safe when I looked" and "it is safe now".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "check", rename_all = "kebab-case")]
pub enum Validity {
    /// The machine still has the host key the fleet enrolled.
    HostKey {
        host: String,
        fingerprint: String,
    },
    /// It is still the same installation.
    MachineId {
        host: String,
        machine_id: String,
    },
    /// Nobody deployed to it in the meantime.
    CurrentSystem {
        host: String,
        store_path: Option<String>,
    },
    Generation {
        host: String,
        generation: u64,
    },
    /// No run other than this one holds the host.
    NoForeignLock {
        host: String,
    },
    Reachable {
        host: String,
    },
    /// The release still names the bytes this plan was made for (V12).
    Artifact {
        host: String,
        store_path: String,
        nar_hash: String,
    },
    /// The group can still afford to lose this member.
    QuorumAllows {
        group: String,
        allowed_unavailable: u32,
    },
}

impl Validity {
    /// Which host this condition is about, for the ones that are about one.
    pub fn host(&self) -> Option<&str> {
        match self {
            Validity::HostKey { host, .. }
            | Validity::MachineId { host, .. }
            | Validity::CurrentSystem { host, .. }
            | Validity::Generation { host, .. }
            | Validity::NoForeignLock { host }
            | Validity::Reachable { host }
            | Validity::Artifact { host, .. } => Some(host),
            Validity::QuorumAllows { .. } => None,
        }
    }
}

/// One step of the plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Action {
    /// Position in the plan, from 1. Stable: a journal entry names a step by
    /// this number and a receipt lines up with the plan it came from.
    pub seq: u32,
    pub host: String,
    pub kind: ActionKind,
    /// What is there now, in whatever terms the step is about. Null when
    /// nobody could say.
    pub current: Option<String>,
    /// What should be there afterwards.
    pub desired: Option<String>,
    /// What the planner checked and found true, as sentences. Evidence for
    /// a reader; [`Action::validity`] is what the executor re-checks.
    pub preconditions: Vec<String>,
    pub depends_on: Vec<Dependency>,
    /// Which round of the rollout this belongs to. Hosts of one wave may run
    /// at the same time; a host of wave n+1 starts after every host of wave
    /// n is committed.
    pub wave: u32,
    /// What must not run beside this step. It is the host id: a host is ONE
    /// interruption unit, so its own steps are strictly ordered, and two
    /// hosts of the same wave have different groups and may go at once.
    pub parallel_group: String,
    pub disruption: Disruption,
    pub reboot_required: bool,
    pub approval_class: ApprovalClass,
    pub rollback: Rollback,
    pub validity: Vec<Validity>,
    /// Null for a step that may run. A sentence for one that may not — and
    /// a blocked step is never silently dropped, because a plan that leaves
    /// out what it refused is a plan that looks smaller than the job.
    pub blocked: Option<String>,

    // --- lane 3-integration: what a provider is handed --------------------
    /// The three values a hypervisor has to load for an
    /// [`ActionKind::ProviderReboot`], and nothing on any other step.
    ///
    /// In the plan and not only in the release, for the same reason the
    /// observation is in the plan: the halt is read by an adapter that has a
    /// plan and a run id, and a step that says "reboot it" without saying
    /// WITH WHAT is a step nobody can carry out. It is part of the
    /// `plan_id`, so an approval for a reboot into one kernel can never be
    /// carried over to a reboot into another.
    ///
    /// Absent — not null — on every other step and in every plan without a
    /// direct-boot host, so that a plan of an all-uefi fleet hashes to
    /// exactly what it hashed to before this field existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_boot: Option<crate::release::DirectBoot>,
    // --- end lane 3-integration -------------------------------------------
}

impl Action {
    pub fn is_blocked(&self) -> bool {
        self.blocked.is_some()
    }
}

// ---------------------------------------------------------------------------
// Hosts, groups, and what nobody knows
// ---------------------------------------------------------------------------

/// What the plan concluded about one host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HostVerdict {
    /// It already runs what the release says, and it booted it. Two steps,
    /// neither of which touches anything (V10).
    Unchanged,
    /// It will be taken forward.
    Change,
    /// Something is in the way. The reason says what.
    Blocked,
    /// Nobody could reach it, and it is in the selection anyway — it does
    /// not disappear from a plan because it was down when somebody looked.
    Unreachable,
    /// Installed and without an identity in this fleet. Never "healthy",
    /// and an upgrade cannot act on it.
    Unenrolled,
}

impl HostVerdict {
    /// Whether nothing may be done to this host in this plan.
    pub fn blocks(self) -> bool {
        matches!(
            self,
            HostVerdict::Blocked | HostVerdict::Unreachable | HostVerdict::Unenrolled
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            HostVerdict::Unchanged => "unchanged",
            HostVerdict::Change => "change",
            HostVerdict::Blocked => "blocked",
            HostVerdict::Unreachable => "unreachable",
            HostVerdict::Unenrolled => "unenrolled",
        }
    }
}

impl std::fmt::Display for HostVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad(self.as_str())
    }
}

/// The plan's summary of one host: what it is, what it will be, and where in
/// the rollout it sits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostPlan {
    pub verdict: HostVerdict,
    /// Every sentence behind the verdict, in the order they were found. A
    /// host with three problems has three sentences, because fixing one and
    /// running again to find the next is how an afternoon disappears.
    pub reasons: Vec<String>,
    pub current_system: Option<String>,
    pub desired_system: String,
    /// What the release says the desired system hashes to. A rebuild that
    /// keeps the path and changes the bytes is a different plan (V12).
    pub desired_nar_hash: String,
    pub reboot_required: bool,
    /// The canary class: hosts that share a kernel, a hypervisor and the
    /// hardware around them. Evidence from one of them is evidence for the
    /// others and for nobody else.
    pub class: String,
    pub canary: bool,
    pub wave: u32,
    pub groups: Vec<String>,
}

/// What the plan worked out about a group, from the OBSERVATION.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GroupView {
    pub kind: GroupKind,
    pub size: u32,
    /// Members that are down, unreachable, or whose etcd nobody could ask.
    /// Counted from what was seen, never from what was declared.
    pub unhealthy_now: u32,
    /// How many more members may be taken down at once. Zero means every
    /// interrupting step in this group is blocked.
    pub allowed_unavailable: u32,
    pub singleton: bool,
    /// Why the whole group is blocked, when it is: a lost quorum, or a
    /// membership that is not the one the inventory declares.
    pub blocked: Option<String>,
}

/// Something this tool does not know and will not pretend to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Unknown {
    /// Null when it is about the plan rather than about one host.
    pub host: Option<String>,
    pub reason: String,
}

/// An approval this plan needs, and — once granted — who granted it.
///
/// `bound_plan_id` is the point: an approval is for THIS plan. A grant
/// carried over from a plan somebody read yesterday approves yesterday's
/// plan, and the ids make that unmistakable rather than a matter of care.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    pub class: ApprovalClass,
    pub bound_plan_id: String,
    pub granted_by: Option<String>,
    pub granted_at: Option<DateTime<Utc>>,
}

/// Which hosts this plan is about — decided once, written down, and never
/// evaluated again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    /// What the operator typed, kept beside the answer so a reader can see
    /// what was MEANT as well as what it came to.
    pub expr: String,
    /// The answer, sorted, frozen. `apply` reads this and never the
    /// expression: a label added to a host after the plan was made does not
    /// add the host to the plan.
    pub targets: Vec<String>,
    /// Selected hosts nobody could reach when the plan was made. They stay
    /// in `targets` — a host does not leave a rollout by being down — and
    /// their steps are blocked.
    pub required_unreachable: Vec<String>,
}

// ---------------------------------------------------------------------------
// The plan
// ---------------------------------------------------------------------------

/// `plan.json`: one release, one observation, one order, one id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeploymentPlan {
    pub schema: String,
    /// sha256 over everything below except this field, `created_at` and
    /// `expires_at`. The last two say WHEN the question was asked; the same
    /// release and the same observation asked twice are the same plan, and
    /// that is what makes an approval quotable.
    pub plan_id: String,
    pub release_id: String,
    pub manifest_id: String,
    pub created_at: DateTime<Utc>,
    /// After this, `apply` refuses: the observation this plan reasoned from
    /// is too old to act on.
    pub expires_at: DateTime<Utc>,
    pub kind: PlanKind,
    pub selection: Selection,
    /// The snapshot this plan was made from, embedded. A plan that does not
    /// carry its facts cannot be argued with afterwards.
    pub observation: Observations,
    /// What each selected host's secrets SHOULD be, read off the
    /// OPERATOR's disk when the plan was made: `secret_refs[].id` to
    /// `sha256:<hex>` for a file whose content may be compared, and
    /// `present` for one whose may not (lane 3B).
    ///
    /// The second half of the comparison the action `deliver-secret` comes
    /// out of; the first half is `observation.hosts.<id>.credentials`. It
    /// is in the plan rather than only in the planner's head for the same
    /// reason the observation is: a plan that says a file has to be
    /// delivered and does not say what it compared is a plan nobody can
    /// argue with. It is part of the `plan_id`, so a plan made before a
    /// certificate was issued and one made after are two plans.
    ///
    /// A host with nothing to compare is simply absent, and so is a secret
    /// whose local file is not there — which is what the planner turns into
    /// a blocked host with `keys csr` and `keys issue` in the sentence.
    #[serde(default)]
    pub expected_credentials: BTreeMap<String, BTreeMap<String, String>>,
    /// Where each selected host is reached, frozen with the selection. A
    /// target set is only frozen if the addresses are frozen with it.
    pub endpoints: BTreeMap<String, Endpoint>,
    pub groups: BTreeMap<String, GroupView>,
    pub hosts: BTreeMap<String, HostPlan>,
    pub actions: Vec<Action>,
    pub unknowns: Vec<Unknown>,
    /// Every class this plan needs, once each. The gate for
    /// `--approve <class>=<plan_id>`.
    pub approvals: Vec<Approval>,

    // --- lane 3A: first installation ------------------------------------
    /// Whether an `install` plan may act on a disk that already carries an
    /// installation.
    ///
    /// Part of the plan and therefore part of the `plan_id`, which is the
    /// whole point: an approval is bound to a plan id, so approving a plan
    /// that installs two blank machines can never be carried over to one
    /// that reinstalls a running host. Always false for every other kind.
    pub reinstall: bool,
    // --- end lane 3A ----------------------------------------------------

    // --- lane 5A: what a rotation is about ------------------------------
    /// The key rotation this plan carries out, per host.
    ///
    /// It is in the plan and therefore in the `plan_id`, and that is the
    /// point: `keys rotate` prepares the key on the HOST and issues the
    /// certificate on the WORKSTATION before there is anything to plan, so
    /// the plan is the document that says which key and which certificate
    /// those were. A plan made for one prepared key can never be applied
    /// against another — the host would answer `prepare` with a different
    /// public key and the run would stop there.
    ///
    /// Absent on every plan that is not a rotation, so no other plan's id
    /// changed when this field arrived.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub rotations: BTreeMap<String, KeyRotation>,
    // --- end lane 5A ----------------------------------------------------
}

// --- lane 5A -----------------------------------------------------------
/// One key rotation: which key, which certificate, and what the host has to
/// answer with at each phase.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct KeyRotation {
    /// `identity` or `serving`.
    pub kind: String,
    /// The name the new key asked for, so that `prepare` asks the host for
    /// the same one it was prepared with.
    pub subject: String,
    /// `<pki.dir>/<kind>.key` on the host. The new one lives beside it as
    /// `.next` until the switch.
    pub key_path: String,
    /// `<pki.dir>/<kind>.crt` on the host.
    pub cert_path: String,
    /// The new certificate in the operator's repository, relative to it.
    pub source: String,
    /// `sha256` of the public half of the prepared key, hex. What the host
    /// has to answer `prepare` with — the one thing that ties this plan to
    /// that key.
    pub public_key_sha256: String,
    /// `sha256:<hex>` of the new certificate: what `overlap` puts there and
    /// what `verify` reads back off the host.
    pub cert_sha256: String,
    /// The serial the CA gave it, for the receipt and for a later
    /// revocation of the certificate this one replaces.
    pub serial: Option<String>,
    /// Who owns the certificate on the host, and with which mode.
    pub owner: String,
    pub mode: String,
    /// The units that read this pair and are restarted by the switch.
    pub units: Vec<String>,
}
// --- end lane 5A -------------------------------------------------------

impl DeploymentPlan {
    pub fn from_json(text: &str, origin: &str) -> Result<DeploymentPlan> {
        let plan: DeploymentPlan = crate::manifest::parse_checked(text, origin, PLAN_SCHEMA)?;
        if !plan.id_matches()? {
            bail!(
                "{origin} carries the id {} and its content hashes to {}; \
                 it was edited after it was planned.",
                plan.plan_id,
                plan.content_id()?
            );
        }
        Ok(plan)
    }

    pub fn to_json(&self) -> Result<Vec<u8>> {
        let mut bytes = serde_json::to_vec_pretty(self)
            .map_err(|e| anyhow::anyhow!("writing the plan as json failed: {e}"))?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    pub fn id_matches(&self) -> Result<bool> {
        Ok(self.content_id()? == self.plan_id)
    }

    /// What this plan hashes to.
    ///
    /// Computed over a copy whose approvals carry no `bound_plan_id`: an
    /// approval is bound to the plan it belongs to, so that binding cannot
    /// be part of what the plan hashes to — the id would have to contain
    /// itself. Everything else about an approval, the class above all, is in
    /// the hash, because a plan that needs one more of them is a different
    /// plan.
    pub fn content_id(&self) -> Result<String> {
        let mut unbound = self.clone();
        for approval in &mut unbound.approvals {
            approval.bound_plan_id = String::new();
        }
        content_id(IdKind::Plan, &unbound)
    }

    /// Whether anything in this plan may not run.
    pub fn is_blocked(&self) -> bool {
        self.actions.iter().any(Action::is_blocked)
    }

    /// Every step that may not run, with its sentence.
    pub fn blocked_reasons(&self) -> Vec<String> {
        let mut out = Vec::new();
        for action in &self.actions {
            if let Some(why) = &action.blocked {
                out.push(format!("{} on {}: {why}", action.kind, action.host));
            }
        }
        out
    }

    pub fn actions_for<'a>(&'a self, host: &str) -> Vec<&'a Action> {
        self.actions.iter().filter(|a| a.host == host).collect()
    }

    /// The highest wave any step of this plan sits in.
    pub fn last_wave(&self) -> u32 {
        self.actions.iter().map(|a| a.wave).max().unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Selection
// ---------------------------------------------------------------------------

/// The keys a selector understands, in the order the error message lists
/// them.
const SELECTOR_KEYS: &[&str] = &["host", "group", "role", "profile", "site"];

/// Work out which hosts an expression means.
///
/// `all` · `host=<id>` · `group=<g>` · `role=<r>` · `profile=<p>` ·
/// `site=<s>`; a comma is a union; a leading `!` takes away. An exclusion
/// needs something to take away from, so it may not come first.
///
/// Every unknown name is an error with the list of known ones. A selector
/// that silently matches nothing is how a rollout quietly skips the host it
/// was written for.
pub fn select(resolved: &ResolvedFleet, expr: &str) -> Result<Vec<String>> {
    let trimmed = expr.trim();
    if trimmed.is_empty() {
        bail!(
            "an empty selector selects nothing. Write `all`, or a term such as \
             `group=cloud`, `role=agent`, `host=<id>`."
        );
    }

    let mut chosen: BTreeSet<String> = BTreeSet::new();
    let mut had_inclusion = false;

    for raw in trimmed.split(',') {
        let term = raw.trim();
        if term.is_empty() {
            bail!("{expr:?} has an empty term: two commas with nothing between them.");
        }
        let (negated, body) = match term.strip_prefix('!') {
            Some(rest) => (true, rest.trim()),
            None => (false, term),
        };
        if negated && !had_inclusion {
            bail!(
                "{term:?} takes hosts away and nothing has been selected yet. \
                 Put an inclusion first, for example `all,{term}`."
            );
        }
        if body.is_empty() {
            bail!("{term:?} is a `!` with nothing after it.");
        }

        let matched = match_term(resolved, body)?;
        if negated {
            for id in matched {
                chosen.remove(&id);
            }
        } else {
            had_inclusion = true;
            chosen.extend(matched);
        }
    }

    if chosen.is_empty() {
        bail!(
            "{expr:?} selects no host of the fleet {:?}. A plan over nothing is not a plan.",
            resolved.fleet.name
        );
    }
    Ok(chosen.into_iter().collect())
}

/// One term, resolved to host ids. Sorted by construction (the fleet is
/// keyed by id).
fn match_term(resolved: &ResolvedFleet, term: &str) -> Result<Vec<String>> {
    if term == "all" {
        return Ok(resolved.hosts.keys().cloned().collect());
    }
    let Some((key, value)) = term.split_once('=') else {
        bail!(
            "{term:?} is not a selector. Write `all` or `<key>=<value>` with one of: {}.",
            SELECTOR_KEYS.join(", ")
        );
    };
    let (key, value) = (key.trim(), value.trim());
    if value.is_empty() {
        bail!("{term:?} has no value after the `=`.");
    }

    match key {
        "host" => {
            if !resolved.hosts.contains_key(value) {
                bail!("{}", no_such_host(resolved, value));
            }
            Ok(vec![value.to_string()])
        }
        "group" => {
            if !resolved.groups.contains_key(value) {
                bail!(
                    "no group is called {value:?}. The fleet has: {}.",
                    list(resolved.groups.keys())
                );
            }
            // From the hosts, not from `group.members`: the two agree by
            // construction (`resolve` checks it), and taking it from the
            // hosts means a group is whatever the hosts say it is.
            Ok(hosts_where(resolved, |h| {
                h.groups.iter().any(|g| g == value)
            }))
        }
        "role" => {
            let known: BTreeSet<&String> = resolved.hosts.values().flat_map(|h| &h.roles).collect();
            if !known.iter().any(|r| *r == value) {
                bail!(
                    "no host has the role {value:?}. The fleet's roles are: {}.",
                    list(known.into_iter())
                );
            }
            Ok(hosts_where(resolved, |h| {
                h.roles.iter().any(|r| r == value)
            }))
        }
        "profile" => {
            let known: BTreeSet<&String> =
                resolved.hosts.values().flat_map(|h| &h.profiles).collect();
            if !known.iter().any(|p| *p == value) {
                bail!(
                    "no host uses the profile {value:?}. The fleet's profiles are: {}.",
                    list(known.into_iter())
                );
            }
            Ok(hosts_where(resolved, |h| {
                h.profiles.iter().any(|p| p == value)
            }))
        }
        "site" => {
            let known: BTreeSet<&String> = resolved
                .hosts
                .values()
                .filter_map(|h| h.site.as_ref())
                .collect();
            if !known.iter().any(|s| *s == value) {
                bail!(
                    "no host is at the site {value:?}. The fleet's sites are: {}.",
                    list(known.into_iter())
                );
            }
            Ok(hosts_where(resolved, |h| h.site.as_deref() == Some(value)))
        }
        other => bail!(
            "{other:?} is not a selector key. This tool knows: {}.",
            SELECTOR_KEYS.join(", ")
        ),
    }
}

/// The sentence for a host that is not there — which says something
/// different when the manifest only ever covered part of the fleet.
fn no_such_host(resolved: &ResolvedFleet, id: &str) -> String {
    if resolved.partial {
        format!(
            "this manifest covers {} and was resolved with --hosts, so it knows nothing \
             about {id}. Resolve the whole fleet, or take {id} out of the selection.",
            list(resolved.hosts.keys())
        )
    } else {
        format!(
            "the fleet {:?} has no host {id}. It has: {}.",
            resolved.fleet.name,
            list(resolved.hosts.keys())
        )
    }
}

fn hosts_where(
    resolved: &ResolvedFleet,
    keep: impl Fn(&crate::manifest::ResolvedHost) -> bool,
) -> Vec<String> {
    resolved
        .hosts
        .iter()
        .filter(|(_, host)| keep(host))
        .map(|(id, _)| id.clone())
        .collect()
}

fn list<'a>(items: impl Iterator<Item = &'a String>) -> String {
    let all: Vec<&str> = items.map(|s| s.as_str()).collect();
    if all.is_empty() {
        "nothing".to_string()
    } else {
        all.join(", ")
    }
}

// ---------------------------------------------------------------------------
// What the planner is told, beside the release and the observation
// ---------------------------------------------------------------------------

/// How long a plan stays actionable. An hour: long enough to fetch an
/// approval, short enough that the observation it reasoned from is still
/// about the same fleet.
pub const DEFAULT_VALIDITY_SECS: u64 = 3600;

/// How long a target waits for a `confirm` after a switch before it reverts.
/// Five minutes is a readiness check and a look at a dashboard.
pub const CONFIRM_WITHIN_SWITCH_SECS: u64 = 300;

/// The same after an activation that takes effect on the next boot. Fifteen
/// minutes, because the machine has to go down, come up and answer ssh again
/// before anybody can confirm anything.
pub const CONFIRM_WITHIN_BOOT_SECS: u64 = 900;

/// The reference to the operator's own CLI that cordon and drain need.
///
/// Never a secret — the inventory is committed. Without it there is no
/// fallback: an agent's guests would be interrupted without being moved, and
/// D7 says such a step is blocked with a sentence rather than taken anyway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadControl {
    pub cli_config: String,
    pub cli_profile: Option<String>,
}

/// The decisions that belong to the operator rather than to the fleet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanPolicy {
    pub kind: PlanKind,
    pub valid_for_secs: u64,
    // --- lane 3A: first installation ---
    /// `plan --kind install --reinstall`: act on a disk that already
    /// carries an installation. Ignored by every other kind.
    pub reinstall: bool,
    // --- end lane 3A ---
    /// `[operator] cli_config` / `cli_profile` from the inventory. `None`
    /// blocks every interrupting step on a host with the agent role.
    ///
    /// It arrives here rather than out of the manifest because it is a
    /// property of the WORKSTATION and not of the fleet: the same release
    /// planned by somebody who has no cli is a different, more careful plan,
    /// and the plan says so.
    pub workload_control: Option<WorkloadControl>,
    pub confirm_within_switch_secs: u64,
    pub confirm_within_boot_secs: u64,
    /// What the operator's own disk holds for each host's secrets
    /// (`crate::pki::expected_credentials`), host id to
    /// `secret_refs[].id` to `sha256:<hex>` or `present`.
    ///
    /// It arrives with the policy rather than out of the release for the
    /// same reason `workload_control` does: it is a property of the
    /// WORKSTATION. The same release planned on a machine that has not
    /// issued the certificates yet is a different, more careful plan, and
    /// the plan says so.
    pub expected_credentials: BTreeMap<String, crate::pki::ExpectedCredentials>,
    // --- lane 5A ---
    /// What `keys rotate` prepared, per host. A property of the WORKSTATION
    /// like the two above: the key was made on the host and the certificate
    /// was issued here, and a planner that had to go and look would be a
    /// planner with a socket in it.
    pub rotations: BTreeMap<String, KeyRotation>,
    // --- end lane 5A ---
}

impl PlanPolicy {
    pub fn new(kind: PlanKind) -> PlanPolicy {
        PlanPolicy {
            kind,
            valid_for_secs: DEFAULT_VALIDITY_SECS,
            reinstall: false,
            workload_control: None,
            confirm_within_switch_secs: CONFIRM_WITHIN_SWITCH_SECS,
            confirm_within_boot_secs: CONFIRM_WITHIN_BOOT_SECS,
            expected_credentials: BTreeMap::new(),
            // --- lane 5A ---
            rotations: BTreeMap::new(),
            // --- end lane 5A ---
        }
    }

    // --- lane 5A ---
    /// What `keys rotate` prepared, per host.
    pub fn with_rotations(mut self, rotations: BTreeMap<String, KeyRotation>) -> PlanPolicy {
        self.rotations = rotations;
        self
    }
    // --- end lane 5A ---

    pub fn with_workload_control(mut self, control: Option<WorkloadControl>) -> PlanPolicy {
        self.workload_control = control;
        self
    }

    /// What the operator has on disk for each host's secrets (lane 3B).
    pub fn with_expected_credentials(
        mut self,
        expected: BTreeMap<String, crate::pki::ExpectedCredentials>,
    ) -> PlanPolicy {
        self.expected_credentials = expected;
        self
    }
    // --- lane 3A: first installation ---
    pub fn with_reinstall(mut self, reinstall: bool) -> PlanPolicy {
        self.reinstall = reinstall;
        self
    }
    // --- end lane 3A ---
}

// ---------------------------------------------------------------------------
// The planner
// ---------------------------------------------------------------------------

/// Everything worked out about one host before any step exists.
#[derive(Debug, Clone)]
struct HostDecision {
    verdict: HostVerdict,
    reasons: Vec<String>,
    /// Sentences that stop EVERY step but the two that only look.
    stop_all: Vec<String>,
    /// Sentences that stop every step that interrupts something. A host that
    /// changes nothing is untouched by these: a lost quorum is a reason not
    /// to disturb a member, not a reason to refuse to look at one.
    stop_disruptive: Vec<String>,
    current_system: Option<String>,
    reboot_required: bool,
    /// Switched and never booted: nothing to stage, nothing to activate, and
    /// a reboot is the whole job.
    reboot_only: bool,
    /// The reboot this host needs is one only its provider can do
    /// (`boot = "direct"`, lane 3A): there is no boot loader in the machine,
    /// so the kernel that starts is the one the hypervisor was handed.
    ///
    /// Derived rather than asked twice: it decides the STEP
    /// (`provider-reboot` instead of `reboot`) and it decides the way back
    /// of the activation before it (`switch`, never `boot` — the helper
    /// refuses boot mode on a machine with no boot menu, measured in 3A).
    provider_reboot: bool,
    // --- lane 5C ---
    /// This host boots itself out of a loader this flake did not install
    /// (`boot = "grub"`), so it has the switch rollback and no other.
    ///
    /// Separate from `provider_reboot`, because the two differ in who does
    /// the rebooting: a grub host reboots itself (`systemctl reboot`), a
    /// direct host waits for its provider. What they share is the ONE
    /// consequence below — the activation runs `--mode switch`, because
    /// `bootctl set-oneshot` is what a boot-mode rollback is made of and
    /// neither machine has it.
    ///
    /// Found in the lab (L2, 2026-09-23): every VM from
    /// `packages.managed-disk-image` is a legacy-MBR grub guest, the
    /// inventory had no word for one, calling it `uefi` made `apply` pass
    /// `--mode boot`, and the helper refused — "there is no boot fallback
    /// on this host: bootctl says systemd-boot is not installed". Such a
    /// host was not deployable at all as soon as a release touched its
    /// kernel.
    switch_only: bool,
    // --- end lane 5C ---
    /// The system is what the release says and a file on it is not: nothing
    /// to stage, nothing to activate, and putting the file there is the
    /// whole job (lane 3B).
    ///
    /// A shape of its own rather than an ordinary `change`, because an
    /// activation of the system a host already runs would take its lock,
    /// drain its guests and move its profile for a certificate.
    secrets_only: bool,
    /// Whether this host needs its guests got out of the way first.
    needs_maintenance: bool,
    class: String,
    /// 0 for a host whose inventory names its canary class, 1 for one that
    /// only derived the same class. The marked host is the canary.
    canary_rank: u8,
    /// Where this host sits in the tier order of this kind of plan.
    tier_rank: u8,
    preconditions: Vec<String>,
    unknowns: Vec<Unknown>,
}

impl HostDecision {
    fn acts(&self) -> bool {
        self.verdict == HostVerdict::Change
    }
}

/// What may happen, to which host, in which order, and what has to still be
/// true when it does.
///
/// Pure. `now` is a value, the release is the intent, the observation is the
/// fact, the targets say where, and the policy is what the operator brought.
/// The same five produce the same `plan_id` — which is what makes an
/// approval quotable, and what the seventy-host test pins.
pub fn plan(
    release: &ReleaseManifest,
    expr: &str,
    observation: &Observations,
    targets: Option<&Targets>,
    policy: &PlanPolicy,
    now: DateTime<Utc>,
) -> Result<DeploymentPlan> {
    let fleet = &release.resolved_fleet;
    let selection = select(fleet, expr)?;
    let selected: BTreeSet<String> = selection.iter().cloned().collect();

    // Every selected host has to have been built, or this release is not the
    // one this selection is about.
    let unbuilt: Vec<&str> = selection
        .iter()
        .filter(|id| !release.artifacts.contains_key(*id))
        .map(|s| s.as_str())
        .collect();
    if !unbuilt.is_empty() {
        bail!(
            "the release {} has no artifacts for {}; a plan over a host nothing was built \
             for is a plan over nothing.",
            release.release_id,
            unbuilt.join(", ")
        );
    }

    let endpoints = match targets {
        Some(targets) => crate::observation::bind_targets(fleet, targets, &selection)?,
        None => crate::observation::manifest_endpoints(fleet, &selection)?,
    };

    let mut unknowns: Vec<Unknown> = Vec::new();
    if fleet.partial {
        unknowns.push(Unknown {
            host: None,
            reason: format!(
                "the manifest behind this release was resolved with --hosts and covers \
                 {} host(s); whatever else the fleet has was never evaluated and is not in \
                 this plan.",
                fleet.evaluated_hosts.len()
            ),
        });
    }
    if observation.provisional {
        unknowns.push(Unknown {
            host: None,
            reason: "this plan was made from a provisional observation: nothing was asked of \
                     any host, so no statement about health in it is worth anything."
                .to_string(),
        });
    }

    // Groups first: what a group can afford decides what its members may do.
    let (groups, group_unknowns) = group_views(fleet, observation, &selected);
    unknowns.extend(group_unknowns);

    // Then each host on its own.
    let mut decisions: BTreeMap<String, HostDecision> = BTreeMap::new();
    for id in &selection {
        let decision = decide_host(release, id, observation, &groups, policy);
        unknowns.extend(decision.unknowns.iter().cloned());
        decisions.insert(id.clone(), decision);
    }
    // Then the order, from real edges and real capacities.
    let edges = dependencies(fleet, &selection, policy.kind);
    let order = topological(&selection, &decisions, &edges)?;
    let canaries = canaries_of(&order, &decisions);
    let waves = assign_waves(fleet, &order, &decisions, &edges, &groups, &canaries);

    // And only then the steps.
    let mut actions: Vec<Action> = Vec::new();
    let mut classes: BTreeSet<ApprovalClass> = BTreeSet::new();
    for id in &order {
        let wave = waves.get(id).copied().unwrap_or(0);
        let (steps, needed) = steps_for(
            release,
            id,
            &decisions[id],
            observation,
            &groups,
            &edges,
            policy,
            wave,
        );
        actions.extend(steps);
        classes.extend(needed);
    }
    // The plan reads in wave order, then by host, then in the order the
    // steps of that host have to happen. `seq` follows the reading.
    actions.sort_by(|a, b| {
        (a.wave, &a.parallel_group, a.seq).cmp(&(b.wave, &b.parallel_group, b.seq))
    });
    for (index, action) in actions.iter_mut().enumerate() {
        action.seq = index as u32 + 1;
    }

    let required_unreachable: Vec<String> = selection
        .iter()
        .filter(|id| decisions[*id].verdict == HostVerdict::Unreachable)
        .cloned()
        .collect();

    let hosts: BTreeMap<String, HostPlan> = selection
        .iter()
        .map(|id| {
            let decision = &decisions[id];
            let artifacts = &release.artifacts[id];
            (
                id.clone(),
                HostPlan {
                    verdict: decision.verdict,
                    reasons: decision.reasons.clone(),
                    current_system: decision.current_system.clone(),
                    desired_system: artifacts.toplevel.store_path.clone(),
                    desired_nar_hash: artifacts.toplevel.nar_hash.clone(),
                    reboot_required: decision.reboot_required,
                    class: decision.class.clone(),
                    canary: canaries.contains(id),
                    wave: waves.get(id).copied().unwrap_or(0),
                    groups: fleet.hosts[id].groups.clone(),
                },
            )
        })
        .collect();

    let mut plan = DeploymentPlan {
        schema: PLAN_SCHEMA.to_string(),
        plan_id: String::new(),
        release_id: release.release_id.clone(),
        manifest_id: release.manifest_id.clone(),
        created_at: now,
        expires_at: now + chrono::TimeDelta::seconds(policy.valid_for_secs as i64),
        kind: policy.kind,
        selection: Selection {
            expr: expr.trim().to_string(),
            targets: selection,
            required_unreachable,
        },
        observation: observation.clone(),
        expected_credentials: policy
            .expected_credentials
            .iter()
            .filter(|(id, _)| selected.contains(*id))
            .map(|(id, secrets)| (id.clone(), secrets.clone()))
            .collect(),
        endpoints,
        groups,
        hosts,
        actions,
        unknowns,
        approvals: classes
            .into_iter()
            .map(|class| Approval {
                class,
                bound_plan_id: String::new(),
                granted_by: None,
                granted_at: None,
            })
            .collect(),
        // --- lane 3A ---
        // Only an install can reinstall; saying `false` anywhere else keeps
        // the field from being a switch somebody could flip on an upgrade.
        reinstall: policy.kind == PlanKind::Install && policy.reinstall,
        // --- end lane 3A ---
        // --- lane 5A ---
        // Only a rotation rotates, and only for the hosts it is about.
        rotations: if policy.kind == PlanKind::KeysRotate {
            policy
                .rotations
                .iter()
                .filter(|(id, _)| selected.contains(*id))
                .map(|(id, r)| (id.clone(), r.clone()))
                .collect()
        } else {
            BTreeMap::new()
        },
        // --- end lane 5A ---
    };
    plan.plan_id = plan.content_id()?;
    for approval in &mut plan.approvals {
        approval.bound_plan_id = plan.plan_id.clone();
    }
    Ok(plan)
}

/// The first host of each class IN THE ORDER, among the hosts that are
/// actually going to move. A canary that changes nothing is evidence of
/// nothing.
///
/// Taken from the order rather than from the ids, and that is the whole
/// point. A class is a kernel and the hardware under it, so it can perfectly
/// well span two tiers — the `controller` class of a fleet whose cluster and
/// cloud hosts are the same shape does. The tier order is a safety rule: a
/// node goes forward before the node that gives it orders. A canary is risk
/// reduction. When the two disagree the order wins, and the canary is chosen
/// from what the order permits; the alternative would be a plan that either
/// breaks the tier rule or promises a canary that in fact rolls ninth.
///
/// The operator's own choice still counts, because `canary_rank` is part of
/// how [`topological`] breaks a tie: among hosts the order leaves free, a
/// host whose inventory names its class comes before one that only derived
/// the same class.
fn canaries_of(order: &[String], decisions: &BTreeMap<String, HostDecision>) -> BTreeSet<String> {
    let mut first: BTreeMap<&str, &String> = BTreeMap::new();
    for id in order {
        let decision = &decisions[id];
        if !decision.acts() {
            continue;
        }
        first.entry(decision.class.as_str()).or_insert(id);
    }
    first.values().map(|id| (*id).clone()).collect()
}

// ---------------------------------------------------------------------------
// Groups: what the OBSERVATION says a group can afford
// ---------------------------------------------------------------------------

fn group_views(
    fleet: &ResolvedFleet,
    observation: &Observations,
    selected: &BTreeSet<String>,
) -> (BTreeMap<String, GroupView>, Vec<Unknown>) {
    let mut views = BTreeMap::new();
    let mut unknowns = Vec::new();

    for (id, group) in &fleet.groups {
        // A group nobody in the selection belongs to is not this plan's
        // business, and judging its health would be judging hosts nobody
        // looked at.
        if !group.members.iter().any(|m| selected.contains(m)) {
            continue;
        }
        let size = group.members.len() as u32;
        let singleton = size == 1;
        let mut blocked: Option<String> = None;

        let unhealthy_now = match group.kind {
            GroupKind::Raft => {
                let mut down = 0;
                for member in &group.members {
                    match observation.host(member) {
                        None => down += 1,
                        Some(obs) if !obs.reachable => down += 1,
                        Some(obs) => match &obs.etcd {
                            None => {
                                // D8: no etcd answer from a member is not
                                // "it is fine", it is "nobody knows", and a
                                // quorum worked out from a guess is worse
                                // than no quorum arithmetic at all.
                                down += 1;
                                unknowns.push(Unknown {
                                    host: Some(member.clone()),
                                    reason: format!(
                                        "{member} is a member of the raft group {id} and the \
                                         snapshot carries no etcd answer for it, so it is \
                                         counted as unavailable."
                                    ),
                                });
                            }
                            Some(etcd) if !etcd.healthy => down += 1,
                            Some(_) => {}
                        },
                    }
                }
                down
            }
            // No quorum to lose. A member that is down is recorded and does
            // NOT eat into what the rollout may take down: `max_unavailable`
            // is a statement about the rollout, and there is no invariant
            // here that one more outage would break.
            GroupKind::Compute | GroupKind::Custom => group
                .members
                .iter()
                .filter(|m| observation.host(m).map(|o| !o.reachable).unwrap_or(true))
                .count() as u32,
        };

        let allowed_unavailable = match group.kind {
            GroupKind::Raft => {
                // The raft rule and nothing else: a cluster of n survives the
                // loss of floor((n-1)/2), and whoever is already down has
                // spent that budget.
                let budget = size.saturating_sub(1) / 2;
                let left = budget.saturating_sub(unhealthy_now);
                if singleton {
                    // A group of one has no budget and is not in trouble: it
                    // is the case where an interruption IS an outage, which
                    // is what `approval_class: singleton` says out loud.
                    0
                } else if left == 0 {
                    blocked = Some(format!(
                        "group {id} is at {} of {size}; no further member may go down.",
                        size - unhealthy_now
                    ));
                    0
                } else {
                    let allowed = left.min(group.rollout.max_unavailable);
                    if allowed == 0 {
                        blocked = Some(format!(
                            "group {id} could afford to lose {left} member(s) and its \
                             `rollout.max_unavailable` is 0, so nothing in it can be taken \
                             forward."
                        ));
                    }
                    allowed
                }
            }
            GroupKind::Compute | GroupKind::Custom => {
                if group.rollout.max_unavailable == 0 {
                    blocked = Some(format!(
                        "group {id} allows 0 hosts to be unavailable at once, so nothing in \
                         it can be taken forward. Set `rollout.max_unavailable`."
                    ));
                }
                group.rollout.max_unavailable
            }
        };

        // A membership that is not the declared one is not a rollout problem,
        // it is a different cluster.
        if group.kind == GroupKind::Raft
            && blocked.is_none()
            && let Some((why, note)) = topology_verdict(fleet, id, group, observation)
        {
            blocked = Some(why);
            if let Some(note) = note {
                unknowns.push(Unknown {
                    host: None,
                    reason: note,
                });
            }
        }

        views.insert(
            id.clone(),
            GroupView {
                kind: group.kind,
                size,
                unhealthy_now,
                allowed_unavailable,
                singleton,
                blocked,
            },
        );
    }
    (views, unknowns)
}

/// Compare the etcd membership the fleet declares with the one etcd reports.
///
/// The declaration comes from `effective_settings.etcd.initial_cluster` —
/// etcd's own `name=peer-url,…` spelling, rendered by the one derivation, so
/// comparing against it compares against what the fleet actually configures.
/// Where a fleet renders no such key only the member NAMES can be compared
/// (against a host's id or its name), and the returned note says so rather
/// than letting half a check look like a whole one.
///
/// Returns `(why the group is blocked, a note about how it was compared)`.
fn topology_verdict(
    fleet: &ResolvedFleet,
    id: &str,
    group: &crate::manifest::Group,
    observation: &Observations,
) -> Option<(String, Option<String>)> {
    let mut observed: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut anybody_answered = false;
    for member in &group.members {
        let Some(etcd) = observation.host(member).and_then(|o| o.etcd.as_ref()) else {
            continue;
        };
        // --- lane 4A (and lane L2, which found the same thing in the lab) ---
        // An EMPTY member list is not an answer. `etcdctl member list` on
        // a member that is running always names at least itself, so an
        // empty list means the probe could not ask — the unit is down, or
        // the machine has just rebooted and etcd has not started yet.
        // Reading that as "the membership is empty" turns a member that is
        // down into a MEMBERSHIP CHANGE, which is a different and much
        // worse verdict, and it blocks the whole group.
        //
        // Measured in `vm-kernel-change`: a host came back from the reboot
        // this very rollout asked for, sshd answered at five seconds and
        // etcd at thirteen, and the run stopped with "the etcd membership
        // of group cp is nothing and the fleet declares target". The
        // `anybody_answered` guard below was meant for exactly this case
        // and did not catch it, because a member whose unit is down still
        // produces a view (`observe::etcd_view`). Lane L2 hit the same
        // shape in the lab on 2026-09-23: a fresh managed image carries the
        // etcd unit without starting it, so `plan --kind bootstrap` blocked
        // its own control plane with "etcd does not know box".
        if etcd.members.is_empty() {
            continue;
        }
        // --- end lane 4A ---
        anybody_answered = true;
        for m in &etcd.members {
            observed
                .entry(m.name.clone())
                .or_default()
                .extend(m.peer_urls.iter().cloned());
        }
    }
    if !anybody_answered {
        // Nothing to compare against. The unhealthy count has already
        // blocked this group; a topology verdict on top would be invented.
        return None;
    }

    match declared_peers(fleet, group) {
        Some(declared) => {
            let declared_names: BTreeSet<&String> = declared.keys().collect();
            let observed_names: BTreeSet<&String> = observed.keys().collect();
            if declared_names != observed_names {
                return Some((
                    format!(
                        "the etcd membership of group {id} is {} and the fleet declares {}; \
                         a membership change needs a migration sequence this tool does not \
                         have.",
                        names(&observed_names),
                        names(&declared_names)
                    ),
                    None,
                ));
            }
            for (name, urls) in &declared {
                // Exactly, not "contains": a member that some peers still
                // report at the old address and one peer reports somewhere
                // else is a controller in the middle of moving, and that is
                // the case this check exists for.
                let seen = &observed[name];
                if seen != urls {
                    return Some((
                        format!(
                            "the etcd member {name} of group {id} advertises {} and the fleet \
                             declares {}; a controller that moved needs a migration sequence \
                             this tool does not have.",
                            names(&seen.iter().collect()),
                            names(&urls.iter().collect())
                        ),
                        None,
                    ));
                }
            }
            None
        }
        None => {
            let mut acceptable: BTreeSet<String> = BTreeSet::new();
            for member in &group.members {
                acceptable.insert(member.clone());
                if let Some(host) = fleet.hosts.get(member) {
                    acceptable.insert(host.name.clone());
                }
            }
            let note = Some(format!(
                "group {id} renders no etcd `initial_cluster`, so only the member names were \
                 compared against the inventory and not the addresses they advertise."
            ));
            let stray: BTreeSet<&String> = observed
                .keys()
                .filter(|n| !acceptable.contains(*n))
                .collect();
            if !stray.is_empty() {
                return Some((
                    format!(
                        "etcd reports the member(s) {} in group {id} and the fleet declares \
                         {}; a membership change needs a migration sequence this tool does \
                         not have.",
                        names(&stray),
                        names(&group.members.iter().collect())
                    ),
                    note,
                ));
            }
            let missing: BTreeSet<&String> = group
                .members
                .iter()
                .filter(|m| {
                    let by_name = fleet.hosts.get(*m).map(|h| h.name.as_str());
                    !observed.contains_key(*m)
                        && !by_name.map(|n| observed.contains_key(n)).unwrap_or(false)
                })
                .collect();
            if !missing.is_empty() {
                return Some((
                    format!(
                        "the fleet declares {} in group {id} and etcd does not know {}; a \
                         membership change needs a migration sequence this tool does not have.",
                        names(&group.members.iter().collect()),
                        names(&missing)
                    ),
                    note,
                ));
            }
            None
        }
    }
}

/// `name=url,name=url` out of whichever member renders an `initial_cluster`.
fn declared_peers(
    fleet: &ResolvedFleet,
    group: &crate::manifest::Group,
) -> Option<BTreeMap<String, BTreeSet<String>>> {
    for member in &group.members {
        let Some(host) = fleet.hosts.get(member) else {
            continue;
        };
        let Some(etcd) = host.effective_settings.etcd.as_ref() else {
            continue;
        };
        let Some(text) = etcd.get("initial_cluster").and_then(|v| v.as_str()) else {
            continue;
        };
        let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for entry in text.split(',') {
            let Some((name, url)) = entry.trim().split_once('=') else {
                // Not the spelling etcd uses. Rather than understand half of
                // it, fall back to comparing the names.
                return None;
            };
            // A member may advertise more than one peer url, and etcd
            // writes that as the same name twice.
            out.entry(name.trim().to_string())
                .or_default()
                .insert(url.trim().to_string());
        }
        if !out.is_empty() {
            return Some(out);
        }
    }
    None
}

fn names(set: &BTreeSet<&String>) -> String {
    let all: Vec<&str> = set.iter().map(|s| s.as_str()).collect();
    if all.is_empty() {
        "nothing".to_string()
    } else {
        all.join(", ")
    }
}

// ---------------------------------------------------------------------------
// The hardware preflight
// ---------------------------------------------------------------------------

// --- lane 4A ---

/// What the preflight found out about the machine under the closure.
///
/// Three lists and not a bool, because the three are read by different
/// people: `met` is evidence a reader wants in the plan, `blocked` is what
/// stops the rollout, and `unknown` is the probe admitting it could not ask.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HardwareVerdict {
    pub met: Vec<String>,
    pub blocked: Vec<String>,
    pub unknown: Vec<String>,
}

impl HardwareVerdict {
    pub fn is_clear(&self) -> bool {
        self.blocked.is_empty()
    }
}

/// Is this machine the machine the fleet says it is, and will the release
/// fit on it?
///
/// Pure, and deliberately called TWICE: [`decide_host`] asks it while the
/// plan is made, so that the answer is part of the plan's contract (the
/// `preconditions[]` of the `preflight` step, or the sentence that blocks
/// the host), and `execute`'s preflight asks it again against a FRESH
/// snapshot immediately before the first copy. One implementation, because
/// a second one here would be a second answer somebody has to keep in step
/// with the first.
///
/// What it does NOT do is guess. An empty `pci` list means the probe found
/// no way to ask, not that the machine has no cards — so a declared GPU
/// against an empty list blocks with a sentence that says which of the two
/// happened, rather than reporting a card as missing that nobody looked
/// for.
pub fn hardware_verdict(
    id: &str,
    host: &crate::manifest::ResolvedHost,
    obs: &crate::observation::HostObservation,
    closure_size: Option<u64>,
) -> HardwareVerdict {
    let mut v = HardwareVerdict::default();

    // --- will it fit -------------------------------------------------------
    //
    // The whole closure against the free space, which is the conservative
    // comparison and says so in the sentence: most of a fleet's closure is
    // shared with what the host already runs, so this number is an upper
    // bound on what the copy really needs. The alternative — asking the
    // target which paths it is missing — is a second round trip per host
    // before the one `nix copy` that would tell us anyway, and it would
    // tell us at the moment the disk is already filling up.
    // `None` means nothing is going to be copied onto this host — it runs
    // what the release says, or it only needs a file — and then its free
    // space is nobody's business. A host that needs no closure must not be
    // blocked by a disk nothing is going to be written to.
    match (closure_size, obs.disk_free_nix_bytes) {
        (Some(closure_size), Some(free)) if free < closure_size => v.blocked.push(format!(
            "{id} has {free} byte(s) free on the filesystem that carries /nix and the closure \
             this release builds for it is {closure_size} byte(s). That is the whole closure, \
             and a host already holds most of it — but this tool will not start a copy it \
             cannot finish. Free space on {id} (`meister-activate gc --keep 3`) or take it out \
             of the selection."
        )),
        (Some(closure_size), Some(free)) => v.met.push(format!(
            "{id} has {free} byte(s) free for a closure of {closure_size}"
        )),
        (Some(_), None) => v.unknown.push(format!(
            "nobody could read how much room the store of {id} has, so whether this release \
             fits on it is not known; the copy is the first thing that would find out."
        )),
        (None, _) => {}
    }

    // --- a node that is supposed to run guests ------------------------------
    //
    // Not part of `capabilities`, and on purpose: `kvm` there is an
    // operator's CLAIM about a machine, and a fleet is allowed not to make
    // it. The agent's own code refuses to start without the device ("a node
    // whose whole purpose is running guests would answer every create with
    // the same error", drivers.rs), so for the agent role this is a fact
    // about the role and not about the inventory.
    if host.roles.iter().any(|r| r == "agent") {
        if obs.has_capability("kvm") {
            v.met
                .push(format!("{id} carries the agent role and has /dev/kvm"));
        } else {
            v.blocked.push(format!(
                "{id} carries the agent role and the snapshot found no /dev/kvm. The agent \
                 refuses to start without it, so activating this release would take the node \
                 out of the fleet rather than forward. Load the virtualisation module on {id}, \
                 or take the agent role off it."
            ));
        }
    }

    // --- the cards the inventory names --------------------------------------
    for gpu in &host.hardware.gpus {
        if obs.pci.is_empty() {
            v.blocked.push(format!(
                "the fleet says {id} has a {} at {} and the snapshot carries no PCI list at \
                 all, so nobody looked. A host whose cards cannot be read is not a host to \
                 activate a release on that was built for those cards.",
                gpu.model, gpu.pci
            ));
        } else if obs.has_pci(&gpu.pci) {
            v.met
                .push(format!("{} answers at {} on {id}", gpu.model, gpu.pci));
        } else {
            v.blocked.push(format!(
                "the fleet says {id} has a {} at {} and nothing is at that address. The \
                 machine lists {}. Either the card moved — then correct `hardware.gpus[].pci` \
                 — or it is not in this machine.",
                gpu.model,
                gpu.pci,
                addresses(&obs.pci)
            ));
        }
    }

    // --- the interfaces the inventory names ---------------------------------
    //
    // By MAC and never by name: `hardware.nics[].name` is what the operator
    // calls it, and what the kernel calls it depends on where it is
    // plugged in.
    for nic in &host.hardware.nics {
        if obs.nics.is_empty() {
            v.blocked.push(format!(
                "the fleet says {id} has the interface {} ({}) and the snapshot carries no \
                 interface list at all, so nobody looked.",
                nic.name, nic.mac
            ));
        } else if obs.has_mac(&nic.mac) {
            v.met.push(format!(
                "the interface {} ({}) of {id} answered",
                nic.name, nic.mac
            ));
        } else {
            v.blocked.push(format!(
                "the fleet says {id} has the interface {} with the address {} and no \
                 interface on the machine has it. The machine has {}. A card that was \
                 replaced has a new address, and the inventory has to say so.",
                nic.name,
                nic.mac,
                macs(&obs.nics)
            ));
        }
    }

    // --- what the fleet declared it can do ----------------------------------
    //
    // V19, and the sentence is the one the planner has had since 2B: a
    // capability that is declared and not found is a machine that cannot
    // run what was built for it. It moved here so that the preflight of
    // `apply` asks it again with the same words.
    for capability in &host.hardware.capabilities {
        if obs.has_capability(capability) {
            v.met.push(format!("{id} has {capability}"));
        } else {
            v.blocked.push(format!(
                "the fleet declares that {id} has {capability} and the snapshot did not find \
                 it. A host that is missing a declared capability cannot run what was built \
                 for it."
            ));
        }
    }

    v
}

/// Every systemd unit a MeisterStack module declares, by name.
///
/// The list is a constant and not a prefix rule, because half of these are
/// not called `meister-*`: `etcd`, `alloy` and the six addons are upstream
/// NixOS services that `nix/{etcd,observability,addons}.nix` configure, and
/// an operator's own `etcd.service` would be a different thing with the
/// same name (which is exactly why the test below holds the constant
/// against a real manifest instead of trusting this comment).
///
/// Sorted, so that a reader of the file and a reader of the diff see the
/// same order.
pub const STACK_UNITS: &[&str] = &[
    "alloy.service",
    "etcd.service",
    "garage.service",
    "grafana.service",
    "kanidm-provision.service",
    "kanidm.service",
    "loki.service",
    "meister-addons-dirs.service",
    "meister-agent.service",
    "meister-cloud-controller.service",
    "meister-cluster-controller.service",
    "meister-context.service",
    "prometheus.service",
    "tempo.service",
];

/// What this release brings to a host that this tool cannot model.
///
/// The useful question is the DIFF BETWEEN TWO GENERATIONS and not a diff
/// against an allowlist (lane 4C measured why: of the seventy-five units an
/// agent's generation carries, exactly one is ours — the other
/// seventy-four are NixOS' own, and "everything that is not meister" would
/// be seventy-four unknowns per host, every run, for ever).
///
/// So: the units the release builds, minus the units the running
/// generation already has, minus the ones this stack declares itself. What
/// is left is a unit an operator's own module brings with this release, and
/// what it does when it starts or restarts is not something a plan can
/// predict.
///
/// Two limits, both deliberate and both in the report:
///
/// * A unit BOTH generations have can still have changed its contents. The
///   manifest carries names and not texts (4C: the texts would be a
///   megabyte of shell in a file that is committed and diffed), so this
///   sees what appears and not what changed.
/// * A unit the previous generation had and this one drops cannot be named.
///   The probe lists the whole unit directory of the running system, which
///   also holds the units systemd's own package ships, while the manifest
///   lists only what NixOS was configured with — so a name in the first and
///   not in the second is usually an upstream unit and not a removal. One
///   side of the diff is sound; the other would be a guess.
fn operator_unit_unknowns(
    id: &str,
    host: &crate::manifest::ResolvedHost,
    obs: &crate::observation::HostObservation,
) -> Vec<Unknown> {
    if host.units.is_empty() {
        // A manifest from before this field existed, or a host nothing was
        // evaluated for. Silence is right: there is nothing to diff.
        return Vec::new();
    }
    if obs.generation_units.is_empty() {
        // Not "everything is new". A probe that could not list the
        // directory has said nothing about it, and turning that into one
        // unknown per unit would bury the plan.
        return vec![Unknown {
            host: Some(id.to_string()),
            reason: format!(
                "nobody could list the units {id} is running, so which of the {} unit(s) of \
                 this release are new on it is not known.",
                host.units.len()
            ),
        }];
    }
    let running: BTreeSet<&str> = obs.generation_units.iter().map(String::as_str).collect();
    let arriving: Vec<&str> = host
        .units
        .iter()
        .map(String::as_str)
        .filter(|unit| !running.contains(unit))
        .filter(|unit| !STACK_UNITS.contains(unit))
        .collect();
    if arriving.is_empty() {
        return Vec::new();
    }
    // One entry per HOST and not per unit: ten new units on one machine is
    // one thing to look at, and ten sentences that differ in one word is a
    // plan nobody reads to the end.
    vec![Unknown {
        host: Some(id.to_string()),
        reason: format!(
            "operator-owned unit(s) {} change with this release on {id}; their effect is not \
             modelled.",
            arriving.join(", ")
        ),
    }]
}

fn addresses(devices: &[crate::observation::PciDevice]) -> String {
    if devices.is_empty() {
        return "nothing".to_string();
    }
    devices
        .iter()
        .map(|d| format!("{} ({})", d.address, d.vendor_device))
        .collect::<Vec<_>>()
        .join(", ")
}

fn macs(nics: &[crate::observation::NetworkInterface]) -> String {
    if nics.is_empty() {
        return "nothing".to_string();
    }
    nics.iter()
        .map(|n| format!("{} ({})", n.name, n.mac))
        .collect::<Vec<_>>()
        .join(", ")
}

// --- end lane 4A ---

// ---------------------------------------------------------------------------
// One host
// ---------------------------------------------------------------------------

fn decide_host(
    release: &ReleaseManifest,
    id: &str,
    observation: &Observations,
    groups: &BTreeMap<String, GroupView>,
    policy: &PlanPolicy,
) -> HostDecision {
    let fleet = &release.resolved_fleet;
    let host = &fleet.hosts[id];
    let artifacts = &release.artifacts[id];
    let desired = &artifacts.toplevel.store_path;

    // --- lane 3A: first installation ---
    // An install asks a different question of the same facts, so it gets
    // its own function rather than five `if kind == Install` scattered
    // through this one: here an unreachable host is the NORMAL case and a
    // host that answers is the one that has to be argued about.
    if policy.kind == PlanKind::Install {
        return decide_install_host(release, id, observation, policy);
    }
    // --- end lane 3A ---
    // --- lane 5A: a list, and nothing else ---
    // A revocation is not a rollout. What this plan may do to a host is put
    // one public file on it; whether that host also owes a kernel is not
    // this plan's business, and answering it here would turn "take a
    // certificate back" into "roll the fleet forward".
    if policy.kind == PlanKind::KeysRevoke {
        return decide_revoke_host(release, id, observation, policy);
    }
    if policy.kind == PlanKind::KeysRotate {
        return decide_rotate_host(release, id, observation, policy);
    }
    // --- end lane 5A ---
    // --- lane 5B: a host that leaves ---
    // A retirement is a revocation seen from the other side. The host that
    // is going is not in this selection at all (`retire` writes
    // `all,!host=<id>`); what the plan does is carry the list that says so
    // to everybody who reads one. Nothing is deleted anywhere, and the
    // machine itself is never touched: it keeps its disk, its data and its
    // files, and what it loses is the right to be believed.
    if policy.kind == PlanKind::Retire {
        return decide_revoke_host(release, id, observation, policy);
    }
    // --- end lane 5B ---

    let mut d = HostDecision {
        verdict: HostVerdict::Change,
        reasons: Vec::new(),
        stop_all: Vec::new(),
        stop_disruptive: Vec::new(),
        current_system: None,
        reboot_required: false,
        reboot_only: false,
        provider_reboot: false,
        switch_only: false,
        secrets_only: false,
        needs_maintenance: false,
        class: class_of(host),
        canary_rank: u8::from(host.rollout.canary_class.is_none()),
        tier_rank: tier_rank(host, policy.kind),
        preconditions: Vec::new(),
        unknowns: Vec::new(),
    };

    // A context host is not served by closures at all. Saying so is the
    // honest answer; planning an activation for it would be planning
    // something that cannot happen.
    if host.deployment == crate::manifest::Deployment::Context {
        d.stop_all.push(format!(
            "{id} is deployed as `context`: its image comes from somewhere else and its \
             binaries are pushed, so a closure is not how it is taken forward. The push \
             that serves such a host lives in the lab repository now \
             (`~/git/meisterstack-lab/legacy/push.sh`), and it is not this tool: migrate \
             the host to `deployment = \"nixos\"` to have it planned here."
        ));
        return settle(d, HostVerdict::Blocked);
    }

    // Nothing was asked of anybody.
    if observation.provisional {
        d.stop_disruptive.push(
            "this plan was made without an observation, so nothing is known about this host; \
             every step that would interrupt it needs an online observation."
                .to_string(),
        );
        // Without a snapshot nobody can say the kernel is unchanged, and
        // "probably not" is not an answer a reboot class accepts.
        d.reboot_required = true;
        d.needs_maintenance = true;
        return settle(d, HostVerdict::Blocked);
    }

    let Some(obs) = observation.host(id) else {
        d.stop_all.push(format!(
            "the snapshot taken at {} has no entry for {id}. It is in the selection and it \
             stays in the plan; nothing may be done to it until somebody has looked.",
            observation.taken_at
        ));
        d.reboot_required = true;
        return settle(d, HostVerdict::Unreachable);
    };

    if let Some(reason) = &obs.unknown_reason {
        d.stop_all.push(format!(
            "the snapshot does not trust its own answer about {id}: {reason}"
        ));
    }
    if !obs.reachable {
        d.stop_all
            .push(format!("{id} did not answer when the snapshot was taken."));
        d.reboot_required = true;
        return settle(d, HostVerdict::Unreachable);
    }

    // --- identity, which is two things and not one ------------------------
    //
    // SSH enrollment is the host key in the operator's `known_hosts` (D10).
    // Every connection this tool makes runs with `StrictHostKeyChecking=yes`
    // against that file, so a host the fleet has no key for cannot be talked
    // to AT ALL — not by an upgrade and not by a bootstrap either. A
    // bootstrap does not create it: `keys enroll` does, from a fingerprint a
    // person read off a console or an installer's output.
    //
    // The SERVICE identity is a certificate, and that is what a bootstrap
    // delivers. A host that answers on a known key and carries no
    // certificate yet is exactly what `--kind bootstrap` is for.
    //
    // Conflating the two would make a bootstrap plan steps over a transport
    // that cannot open, and the failure would arrive as an ssh error in the
    // middle of a rollout rather than as a sentence before it.
    match (
        &host.ssh.host_key_fingerprint,
        &obs.identity.host_key_fingerprint,
    ) {
        (Some(declared), Some(seen)) if declared != seen => d.stop_all.push(format!(
            "identity changed: the fleet has {id} enrolled with the host key {declared} and \
             {seen} answered. Either the machine was reinstalled — then enroll it again with \
             `keys enroll {id} --fingerprint {seen} --replace --reason <why>` — or it is not \
             the machine you think it is."
        )),
        (Some(declared), Some(_)) => d.preconditions.push(format!(
            "{id} answered with the enrolled host key {declared}"
        )),
        (Some(_), None) => d.stop_all.push(format!(
            "the snapshot does not say which host key answered for {id}, so this tool cannot \
             tell whether it is the machine the fleet enrolled."
        )),
        (None, _) => {
            d.stop_all.push(format!(
                "the fleet has no host key for {id}, so nothing can connect to it: every ssh \
                 this tool makes checks the key against the operator's known_hosts. Run \
                 `keys enroll {id} --fingerprint SHA256:…` first, with the fingerprint from \
                 the machine's console or its installer output — a bootstrap delivers \
                 certificates, it does not enroll a host key."
            ));
            d.current_system = obs.current_system.clone();
            d.reboot_required = true;
            return settle(d, HostVerdict::Unenrolled);
        }
    }
    if !obs.enrolled {
        // No service identity of its own. That is the state a bootstrap
        // exists to leave behind, and the state an upgrade cannot act from.
        if policy.kind == PlanKind::Bootstrap {
            d.preconditions.push(format!(
                "{id} has no identity of its own yet, which is what this bootstrap delivers"
            ));
        } else {
            d.stop_all.push(format!(
                "{id} is installed and reports no identity of its own. An upgrade acts on a \
                 host that is already part of the fleet; `plan --kind bootstrap` is what \
                 delivers the certificates that make it one."
            ));
            d.current_system = obs.current_system.clone();
            d.reboot_required = true;
            return settle(d, HostVerdict::Unenrolled);
        }
    }

    // --- lane 3B: what a bootstrap has to be able to deliver -------------
    //
    // Only in a bootstrap, and only for a file the host has NOT got. An
    // upgrade acts on a host that already carries its identity (the check
    // above refuses one that does not), and a certificate the operator
    // keeps somewhere this tool was never told about is not a reason to
    // refuse to roll a running fleet forward. A bootstrap is the other
    // case: its whole job is to put the files there, and a bootstrap that
    // cannot is a bootstrap that would leave the host half made.
    if policy.kind == PlanKind::Bootstrap {
        let expected = policy.expected_credentials.get(id);
        // One sentence per FILE, not per reference. The one derivation
        // writes a `secret_refs` entry per file AND unit (the id is
        // `<file>-<role>`), so a host with two controller tiers has two
        // references to one `identity.crt` — and saying the same thing
        // twice is how a blocked plan becomes unreadable.
        let mut said: BTreeSet<&str> = BTreeSet::new();
        for secret in &host.secret_refs {
            if secret.source.kind == crate::manifest::SecretSourceKind::TargetGenerated {
                continue;
            }
            let on_the_host = obs.credentials.get(&secret.id).cloned().flatten();
            if on_the_host.is_some() {
                continue;
            }
            if expected.is_some_and(|e| e.contains_key(&secret.id)) {
                continue;
            }
            if !said.insert(secret.target_path.as_str()) {
                continue;
            }
            d.stop_all.push(match secret.source.kind {
                crate::manifest::SecretSourceKind::MeisterCa => format!(
                    "{id} has no {} and this workstation has nothing to deliver: nobody has \
                     issued it. Run `keys csr --host {id} --kind {}` — the key is made on the \
                     host and only the request travels — and then `keys issue --host {id} \
                     --kind <node|cluster|cloud|serving> …`.",
                    secret.target_path,
                    if crate::observe::is_certificate(&secret.target_path)
                        && secret.target_path.contains("serving")
                    {
                        "serving"
                    } else {
                        "identity"
                    }
                ),
                crate::manifest::SecretSourceKind::OperatorFile => format!(
                    "{id} has no {} and this workstation has no file to deliver for it: the \
                     fleet says it comes from {} (an operator file, under `[operator] \
                     ca_dir`), and there is nothing there.",
                    secret.target_path, secret.source.reference
                ),
                crate::manifest::SecretSourceKind::TargetGenerated => unreachable!("skipped"),
            });
        }
    }

    // --- somebody else is already here -----------------------------------
    if !obs.open_txns.is_empty() {
        let ids: Vec<&str> = obs.open_txns.iter().map(|t| t.id.as_str()).collect();
        d.stop_all.push(format!(
            "{id} still has the transaction(s) {} open. An interrupted run is continued with \
             `apply --resume <run-id>` and never by starting again: the target knows whether \
             the last activation was confirmed, and this plan does not.",
            ids.join(", ")
        ));
    }
    if let Some(lock) = &obs.lock {
        d.stop_all.push(format!(
            "the run {} has held {id} since {} (operator {}, pid {}). Continue that run with \
             `apply --resume {}`, or take it over with `apply --takeover {}` once you know it \
             is gone.",
            lock.run_id, lock.acquired_at, lock.operator, lock.pid, lock.run_id, lock.run_id
        ));
    }

    // --- what has to be there --------------------------------------------
    for entry in host.persistence.iter().filter(|p| p.required) {
        if obs.is_mounted(&entry.path) {
            d.preconditions.push(format!(
                "{} is mounted from {}",
                entry.path, entry.device_ref
            ));
        } else {
            d.stop_all.push(format!(
                "{id} has no filesystem mounted at {}, and the fleet declares it required \
                 (from {}). There is no fallback to the root disk: a service that writes its \
                 data to the wrong disk is worse than one that does not start.",
                entry.path, entry.device_ref
            ));
        }
    }
    // --- what runs, what should run, and what booted ----------------------
    d.current_system = obs.current_system.clone();
    let Some(current) = obs.current_system.as_ref() else {
        d.stop_all.push(format!(
            "the snapshot does not say what {id} is running, so this plan cannot tell an \
             upgrade from a no-op."
        ));
        d.reboot_required = true;
        return settle(d, HostVerdict::Blocked);
    };
    let current_is_desired = current == desired;
    let next_is_desired = obs.next_boot_system.as_deref() == Some(desired.as_str());
    let booted_is_desired = obs.booted_system.as_deref() == Some(desired.as_str());

    // Wanted, next boot and running are three separate facts, and this is
    // the one place all three are put side by side.
    let unchanged =
        current_is_desired && next_is_desired && (obs.booted_system.is_none() || booted_is_desired);
    if unchanged && obs.booted_system.is_none() {
        d.unknowns.push(Unknown {
            host: Some(id.to_string()),
            reason: format!(
                "{id} runs and will boot what the release says, and nobody could read which \
                 system it actually booted; that it needs nothing rests on the running system \
                 alone."
            ),
        });
    }
    // --- lane 4A: the machine under the closure ---------------------------
    //
    // Room, /dev/kvm, the cards, the interfaces and the declared
    // capabilities (V19), all from the one function `execute`'s preflight
    // asks again with a fresh snapshot. `stop_all` and not
    // `stop_disruptive`: a machine that is not the machine the fleet
    // describes is not a machine to stage a closure onto either — and the
    // preflight step itself stays free, so the finding is REPORTED rather
    // than only refused.
    //
    // Here and not further up, because the ROOM question needs to know
    // whether anything is going to be copied at all: a host that already
    // runs the release is not blocked by a full disk nothing would be
    // written to. Everything else about the machine is asked either way —
    // a card that is gone is worth saying even about a host that needs
    // nothing.
    let hardware = hardware_verdict(
        id,
        host,
        obs,
        (!unchanged).then_some(artifacts.toplevel.closure_size),
    );
    d.preconditions.extend(hardware.met);
    d.stop_all.extend(hardware.blocked);
    for reason in hardware.unknown {
        d.unknowns.push(Unknown {
            host: Some(id.to_string()),
            reason,
        });
    }
    // --- end lane 4A ---

    d.reboot_only = !unchanged && current_is_desired && next_is_desired && !booted_is_desired;
    if d.reboot_only {
        d.preconditions.push(format!(
            "{id} has already been switched to this system and has not booted it"
        ));
    }

    // --- the reboot class --------------------------------------------------
    if !unchanged {
        match &obs.kernel_booted {
            None => {
                d.reboot_required = true;
                d.unknowns.push(Unknown {
                    host: Some(id.to_string()),
                    reason: format!(
                        "nobody could read what kernel {id} booted, so this plan assumes a \
                         reboot is needed. That is the conservative answer: the other one is \
                         either a reboot nobody asked for or a machine that keeps running a \
                         kernel the release replaced."
                    ),
                });
            }
            Some(booted) => {
                let mut differs: Vec<&str> = Vec::new();
                if booted.kernel_store_path != artifacts.boot.kernel_store_path {
                    differs.push("the kernel");
                }
                if booted.initrd_store_path != artifacts.boot.initrd_store_path {
                    differs.push("the initrd");
                }
                if booted.kernel_params_sha256 != artifacts.boot.kernel_params_sha256 {
                    differs.push("the kernel command line");
                }
                if differs.is_empty() {
                    d.preconditions.push(format!(
                        "{id} already boots the kernel this release builds, so it needs no \
                         reboot for it"
                    ));
                } else {
                    d.reboot_required = true;
                    d.preconditions.push(format!(
                        "{} of {id} changed, so it takes effect on the next boot and not \
                         before",
                        differs.join(" and ")
                    ));
                }
            }
        }
        if d.reboot_required && host.rollout.reboot == crate::manifest::RebootPolicy::Never {
            d.stop_disruptive.push(format!(
                "taking {id} forward needs a reboot and its rollout policy says \
                 `reboot = never`. Change the policy for this host, or take it out of the \
                 selection — this tool does not reboot a machine that said no."
            ));
        }
    }

    // --- the guests, and whether they can be got out of the way -----------
    //
    // `obs.enrolled` is in this condition and not only the role, and the
    // case it is about is a BOOTSTRAP: a host that carries no identity of
    // its own has never been able to authenticate to the cluster that hands
    // out work, so there is nothing on it to move. Asking a cluster to
    // cordon a node it has never seen is asking for an error message in the
    // middle of a rollout instead of a rollout. Everywhere else this changes
    // nothing — an upgrade of a host without an identity is `unenrolled` and
    // blocked several screens above.
    d.needs_maintenance = !unchanged && host.roles.iter().any(|r| r == "agent") && obs.enrolled;
    if d.needs_maintenance && policy.workload_control.is_none() {
        d.stop_disruptive.push(format!(
            "{id} carries guests and the inventory has no `[operator] cli_config`, so this \
             tool cannot cordon or drain it. Its guests would be interrupted without being \
             moved. Set `[operator] cli_config` and `cli_profile`, or take {id} out of the \
             selection."
        ));
    }

    // --- what the groups allow --------------------------------------------
    for group in &host.groups {
        if let Some(view) = groups.get(group)
            && let Some(why) = &view.blocked
        {
            d.stop_disruptive.push(why.clone());
        }
    }

    // --- operator modules: not analysed, and it says so --------------------
    if !host.modules.is_empty() {
        d.unknowns.push(Unknown {
            host: Some(id.to_string()),
            reason: format!(
                "{id} imports the operator module(s) {}; operator module effects are not \
                 analysed; check required.",
                host.modules.join(", ")
            ),
        });
    }

    // --- lane 4A: the units the operator owns -----------------------------
    d.unknowns.extend(operator_unit_unknowns(id, host, obs));
    // --- end lane 4A ---

    // --- lane 3B: a file that is not what it should be ------------------
    //
    // A host whose SYSTEM is what the release says can still be missing a
    // certificate, or be holding one that has been renewed here. That is
    // not "unchanged" — something has to happen to it — and it is not an
    // ordinary change either: staging and activating a system the host
    // already runs would take its lock and move its profile for a file.
    let deliveries = pending_deliveries(host, obs, policy.expected_credentials.get(id));
    if unchanged && deliveries > 0 {
        d.secrets_only = true;
        d.preconditions.push(format!(
            "{id} runs what the release says and {deliveries} of its file(s) are not what \
             this repository holds; nothing is staged and nothing is activated"
        ));
    }
    let settled = unchanged && !d.secrets_only;

    // --- lane 3-integration: a kernel this machine does not choose --------
    //
    // On a `boot = "direct"` host the boot half of a release is loaded from
    // OUTSIDE: `next_boot_system` is the system profile, and the hypervisor
    // is what decides which kernel actually starts (3A measured exactly
    // that). So every reboot such a host needs — a new kernel, a new
    // initrd, a new command line, or a switch that was never booted — is a
    // `provider-reboot` and never a `systemctl reboot`, which would bring
    // the machine back on the bytes the provider loaded last time.
    d.provider_reboot = !settled
        && !d.secrets_only
        && (d.reboot_required || d.reboot_only)
        && host.build.boot.mode == crate::manifest::BootMode::Direct;
    // --- lane 5C ---
    // A grub host reboots itself, so the STEP is an ordinary `reboot`. What
    // it cannot do is take a boot back, so the activation in front of that
    // reboot runs in switch mode (`rollback_for` below). Unconditional on
    // the boot mode and not on whether this release reboots: the way back
    // of an activation is a property of the machine.
    d.switch_only = host.build.boot.mode == crate::manifest::BootMode::Grub;
    // --- end lane 5C ---
    if d.provider_reboot && artifacts.direct_boot.is_none() {
        // `release::bind` will not make such a release — it refuses a direct
        // host without a bundle in both directions (3A). This is the second
        // door all the same: a plan is the document an adapter acts on, and
        // a `provider-reboot` whose payload is missing is a step whose whole
        // content would be missing.
        d.stop_all.push(format!(
            "the release carries no direct-boot bundle for {id}, and {id} boots through its \
             provider: taking it forward needs a kernel, an initrd and a command line for \
             somebody to load. Build the release again with a tool that knows the boot mode \
             (`meister-deploy build`)."
        ));
    }
    if d.provider_reboot && host.checks.required.iter().any(|c| c == "booted") {
        // Between the switch and the provider's reboot this host RUNS the
        // release and has BOOTED the previous one — that is what a direct
        // boot mode means, and it is the state the plan asks its operator
        // to confirm in. A required `booted` check makes the verify before
        // that confirmation fail, which would take the switch back and
        // leave the rollout exactly where it started. Saying so here is
        // cheaper than letting a fleet roll itself back once per kernel.
        d.stop_disruptive.push(format!(
            "{id} boots through its provider and its inventory requires the check `booted`. \
             Between the switch and the provider's reboot this host runs the release and has \
             booted the one before it, so that check cannot pass and the verify before the \
             confirmation would take the switch back. Take `booted` out of the required checks \
             of {id} (the `system` check stays required and still compares what it runs), or \
             leave this host to a plan that changes no kernel."
        ));
    }

    let verdict = if !d.stop_all.is_empty() {
        HostVerdict::Blocked
    } else if settled {
        HostVerdict::Unchanged
    } else if !d.stop_disruptive.is_empty() {
        HostVerdict::Blocked
    } else {
        HostVerdict::Change
    };
    if settled {
        d.reboot_required = false;
        d.needs_maintenance = false;
    }
    if d.secrets_only {
        // Nothing boots and nothing stops: the steps are preflight, the
        // lock, the files, a verify and the lock back.
        d.reboot_required = false;
    }
    settle(d, verdict)
}

/// How many of this host's secrets are not what the operator's disk says
/// they should be (lane 3B). The same predicate the steps are built from,
/// asked once before the verdict.
fn pending_deliveries(
    host: &crate::manifest::ResolvedHost,
    obs: &crate::observation::HostObservation,
    expected: Option<&crate::pki::ExpectedCredentials>,
) -> usize {
    host.secret_refs
        .iter()
        .filter(|secret| {
            crate::pki::needs_delivery(
                secret,
                expected.and_then(|e| e.get(&secret.id)),
                obs.credentials.get(&secret.id),
            )
        })
        .count()
}

// --- lane 5A: the rotation plan --------------------------------------------

/// What a `keys-rotate` plan says about one host.
///
/// The preparation has already happened when this runs: `keys rotate` made
/// the key ON THE HOST and had the certificate issued HERE, and what is
/// planned is the five steps that put them in. So the first question is not
/// "what does this host run" but "is this the host that key was made on".
fn decide_rotate_host(
    release: &ReleaseManifest,
    id: &str,
    observation: &Observations,
    policy: &PlanPolicy,
) -> HostDecision {
    let fleet = &release.resolved_fleet;
    let host = &fleet.hosts[id];
    let mut d = HostDecision {
        verdict: HostVerdict::Change,
        reasons: Vec::new(),
        stop_all: Vec::new(),
        stop_disruptive: Vec::new(),
        current_system: None,
        reboot_required: false,
        // A grub host has no boot-mode rollback (lane 5C, N4); a key plan
        // activates nothing, so the flag only has to be the truth about the host.
        switch_only: host.build.boot.mode == crate::manifest::BootMode::Grub,
        reboot_only: false,
        provider_reboot: false,
        // Nothing is staged and nothing is activated: a rotation replaces a
        // pair of files and restarts what reads them.
        secrets_only: true,
        needs_maintenance: false,
        class: class_of(host),
        canary_rank: u8::from(host.rollout.canary_class.is_none()),
        tier_rank: tier_rank(host, policy.kind),
        preconditions: Vec::new(),
        unknowns: Vec::new(),
    };

    let Some(rotation) = policy.rotations.get(id) else {
        d.stop_all.push(format!(
            "there is no prepared rotation for {id} on this workstation. `keys rotate --host \
             {id} --kind identity` makes the new key on the host, has the certificate issued \
             here and writes the plan; a rotation plan cannot be made without those two."
        ));
        return settle(d, HostVerdict::Blocked);
    };

    if observation.provisional {
        d.stop_all.push(
            "this plan was made without an observation, and a rotation is a thing done to a \
             machine that is answering."
                .to_string(),
        );
        return settle(d, HostVerdict::Blocked);
    }
    let Some(obs) = observation.host(id) else {
        d.stop_all.push(format!(
            "the snapshot taken at {} has no entry for {id}.",
            observation.taken_at
        ));
        return settle(d, HostVerdict::Unreachable);
    };
    if !obs.reachable {
        d.stop_all
            .push(format!("{id} did not answer when the snapshot was taken."));
        return settle(d, HostVerdict::Unreachable);
    }
    match (
        &host.ssh.host_key_fingerprint,
        &obs.identity.host_key_fingerprint,
    ) {
        (Some(declared), Some(seen)) if declared != seen => d.stop_all.push(format!(
            "identity changed: the fleet has {id} enrolled with the host key {declared} and \
             {seen} answered. A rotation puts a private key into service; it is not done to a \
             machine nobody can identify."
        )),
        (Some(declared), Some(_)) => d.preconditions.push(format!(
            "{id} answered with the enrolled host key {declared}"
        )),
        (Some(_), None) => d.stop_all.push(format!(
            "the snapshot does not say which host key answered for {id}."
        )),
        (None, _) => {
            d.stop_all.push(format!(
                "the fleet has no host key for {id}. Run `keys enroll {id} --fingerprint \
                 SHA256:…` first."
            ));
            return settle(d, HostVerdict::Unenrolled);
        }
    }
    if !obs.enrolled {
        // A host with no identity of its own has nothing to rotate. That is
        // a bootstrap, and it is a different plan.
        d.stop_all.push(format!(
            "{id} reports no identity of its own, so there is nothing to rotate. \
             `plan --kind bootstrap` is what gives a host its first certificates."
        ));
        return settle(d, HostVerdict::Unenrolled);
    }
    if let Some(lock) = &obs.lock {
        d.stop_all.push(format!(
            "the run {} has held {id} since {} (operator {}, pid {}).",
            lock.run_id, lock.acquired_at, lock.operator, lock.pid
        ));
    }
    if !obs.open_txns.is_empty() {
        let ids: Vec<&str> = obs.open_txns.iter().map(|t| t.id.as_str()).collect();
        d.stop_all.push(format!(
            "{id} still has the transaction(s) {} open; finish that run with `apply --resume \
             <run-id>` before its keys are touched.",
            ids.join(", ")
        ));
    }
    d.preconditions.push(format!(
        "{id} holds a prepared {} key ({}), and the certificate for it is in this repository",
        rotation.kind, rotation.public_key_sha256
    ));

    let verdict = if d.stop_all.is_empty() {
        HostVerdict::Change
    } else {
        HostVerdict::Blocked
    };
    settle(d, verdict)
}

/// The five steps of a rotation, in the order they have to happen.
fn rotate_specs(id: &str, rotation: &KeyRotation) -> Vec<StepSpec> {
    vec![
        step(ActionKind::KeysPrepare, Disruption::None)
            .from("the key in use")
            .to(format!("{} beside it", rotation.public_key_sha256))
            .because(
                "the host is asked for the key it prepared, not told to make one: a second \
                 key would be a second identity, and the certificate that was issued would \
                 be for a key nobody has",
            ),
        step(ActionKind::KeysOverlap, Disruption::None)
            .to(format!("{}.next", rotation.cert_path))
            .because(
                "the certificate lands beside the one in use and nothing reads it yet, so a \
                 run that stops here has changed nothing that is running",
            ),
        step(ActionKind::KeysSwitch, Disruption::Service)
            .from(rotation.cert_path.clone())
            .to(rotation.cert_sha256.clone())
            .because(format!(
                "the prepared pair goes in and the old one goes aside in one move, and {} \
                 read it again",
                if rotation.units.is_empty() {
                    "nothing has to".to_string()
                } else {
                    rotation.units.join(", ")
                }
            )),
        step(ActionKind::KeysVerify, Disruption::None)
            .to(rotation.cert_sha256.clone())
            .because(
                "the host says which certificate it now holds and the required checks say \
                 whether it works with it; a check that fails takes the pair back",
            ),
        step(ActionKind::KeysRemove, Disruption::None)
            .from(format!("{}.prev", rotation.cert_path))
            .to("gone")
            .because(format!(
                "the pair {id} was using before this rotation is dropped, and the rotation is \
                 over"
            )),
    ]
}

// --- lane 5A: the revocation plan ------------------------------------------

/// Every `crl` reference of this host. Empty for a host that reads no list —
/// which is every host of a fleet that has not named `auth.crl`, and is a
/// statement about the fleet rather than about this host.
fn crl_refs(host: &crate::manifest::ResolvedHost) -> Vec<&crate::manifest::SecretRef> {
    host.secret_refs
        .iter()
        .filter(|s| s.kind == crate::manifest::SecretKind::Crl)
        .collect()
}

/// What a `keys-revoke` plan says about one host.
///
/// The same facts as an upgrade's, read for one question: has this host got
/// the list that is on this workstation. Everything else it might owe —
/// a system, a kernel, a certificate — is another plan's business, and
/// mixing them would make a revocation the most dangerous verb in the tool.
fn decide_revoke_host(
    release: &ReleaseManifest,
    id: &str,
    observation: &Observations,
    policy: &PlanPolicy,
) -> HostDecision {
    let fleet = &release.resolved_fleet;
    let host = &fleet.hosts[id];
    let mut d = HostDecision {
        verdict: HostVerdict::Change,
        reasons: Vec::new(),
        stop_all: Vec::new(),
        stop_disruptive: Vec::new(),
        current_system: None,
        reboot_required: false,
        // A grub host has no boot-mode rollback (lane 5C, N4); a key plan
        // activates nothing, so the flag only has to be the truth about the host.
        switch_only: host.build.boot.mode == crate::manifest::BootMode::Grub,
        reboot_only: false,
        provider_reboot: false,
        // A revocation is only ever this shape: preflight, the lock, the
        // file, a verify, the lock back.
        secrets_only: true,
        needs_maintenance: false,
        class: class_of(host),
        canary_rank: u8::from(host.rollout.canary_class.is_none()),
        tier_rank: tier_rank(host, policy.kind),
        preconditions: Vec::new(),
        unknowns: Vec::new(),
    };

    if crl_refs(host).is_empty() {
        // Not a failure and not a gap in this plan: this host's rendered
        // configuration names no revocation list, so there is no file to
        // put anywhere and nothing on it would read one.
        // A precondition and not a `reason`: `settle` keeps the reasons for
        // what STOPS a host, and this host is not stopped — it simply has
        // nothing to read a list with. The sentence travels on its preflight.
        d.preconditions.push(format!(
            "{id} reads no revocation list: its configuration names no `auth.crl`, so a list \
             delivered to it would be a file nobody opens. Name it in the inventory (the \
             fleet renders the path under `meisterstack.pki.dir`) and resolve again."
        ));
        d.secrets_only = false;
        return settle(d, HostVerdict::Unchanged);
    }

    if host.deployment == crate::manifest::Deployment::Context {
        d.stop_all.push(format!(
            "{id} is deployed as `context`: its files are pushed by the adapter in the lab \
             repository (`legacy/push.sh`), not by this plan."
        ));
        return settle(d, HostVerdict::Blocked);
    }
    if observation.provisional {
        d.stop_all.push(
            "this plan was made without an observation, so nobody knows which list any host \
             is holding. A revocation that is not delivered is not a revocation."
                .to_string(),
        );
        return settle(d, HostVerdict::Blocked);
    }
    let Some(obs) = observation.host(id) else {
        d.stop_all.push(format!(
            "the snapshot taken at {} has no entry for {id}, so nobody can say whether it has \
             the new list.",
            observation.taken_at
        ));
        return settle(d, HostVerdict::Unreachable);
    };
    if !obs.reachable {
        // The receipt's job, and V24's honest half: a revocation is in force
        // where it arrived, and the plan names who did not answer.
        d.stop_all.push(format!(
            "{id} did not answer when the snapshot was taken, so it is still serving whatever \
             list it had. Run this plan again when it is back — until then the revocation is \
             in force everywhere else and not there."
        ));
        return settle(d, HostVerdict::Unreachable);
    }
    match (
        &host.ssh.host_key_fingerprint,
        &obs.identity.host_key_fingerprint,
    ) {
        (Some(declared), Some(seen)) if declared != seen => d.stop_all.push(format!(
            "identity changed: the fleet has {id} enrolled with the host key {declared} and \
             {seen} answered."
        )),
        (Some(declared), Some(_)) => d.preconditions.push(format!(
            "{id} answered with the enrolled host key {declared}"
        )),
        (Some(_), None) => d.stop_all.push(format!(
            "the snapshot does not say which host key answered for {id}."
        )),
        (None, _) => {
            d.stop_all.push(format!(
                "the fleet has no host key for {id}, so nothing can connect to it. Run \
                 `keys enroll {id} --fingerprint SHA256:…` first."
            ));
            return settle(d, HostVerdict::Unenrolled);
        }
    }
    if let Some(lock) = &obs.lock {
        d.stop_all.push(format!(
            "the run {} has held {id} since {} (operator {}, pid {}).",
            lock.run_id, lock.acquired_at, lock.operator, lock.pid
        ));
    }
    if !obs.open_txns.is_empty() {
        let ids: Vec<&str> = obs.open_txns.iter().map(|t| t.id.as_str()).collect();
        d.stop_all.push(format!(
            "{id} still has the transaction(s) {} open; finish that run with `apply --resume \
             <run-id>` before a file is written under it.",
            ids.join(", ")
        ));
    }

    let expected = policy.expected_credentials.get(id);
    // Before the comparison and not after it: a workstation with no list has
    // nothing that DIFFERS from what the host holds, so the comparison would
    // come out "nothing to do" — which is the one answer a revocation must
    // never give by accident.
    if expected.is_none_or(|e| crl_refs(host).iter().all(|s| !e.contains_key(&s.id))) {
        d.stop_all.push(format!(
            "{id} reads a revocation list and this workstation has none to deliver. \
             `keys revoke` writes it to `pki/crl.pem` in the repository; run that rather \
             than this plan."
        ));
        return settle(d, HostVerdict::Blocked);
    }
    let pending = crl_refs(host)
        .into_iter()
        .filter(|secret| {
            crate::pki::needs_delivery(
                secret,
                expected.and_then(|e| e.get(&secret.id)),
                obs.credentials.get(&secret.id),
            )
        })
        .count();
    if pending == 0 {
        d.secrets_only = false;
        d.preconditions
            .push(format!("{id} already holds the list this repository has."));
        return settle(d, HostVerdict::Unchanged);
    }
    d.preconditions.push(format!(
        "{id} holds a revocation list that is not the one in this repository"
    ));

    let verdict = if d.stop_all.is_empty() {
        HostVerdict::Change
    } else {
        HostVerdict::Blocked
    };
    settle(d, verdict)
}
// --- end lane 5A -----------------------------------------------------------

// --- lane 3A: first installation ------------------------------------------

/// What an `install` plan says about one host.
///
/// The facts are the same as an upgrade's; the reading of them is not. A
/// host nobody can reach is exactly what an install is FOR, so it is a
/// `change` here and an `unreachable` there. A host that answers and runs a
/// system is the dangerous case — the disk of a running machine is somebody's
/// data — so it is blocked unless the plan says `--reinstall` out loud, and
/// that word is part of the plan id (which is what an approval is bound to).
///
/// What this never does is decide that a disk is blank. Nobody can decide
/// that from a workstation: the serial, the size, the layout's device and
/// the installation mark are all facts about a machine somebody is standing
/// in front of, and `meister-install confirm` is what reads them there.
fn decide_install_host(
    release: &ReleaseManifest,
    id: &str,
    observation: &Observations,
    policy: &PlanPolicy,
) -> HostDecision {
    let fleet = &release.resolved_fleet;
    let host = &fleet.hosts[id];
    let mut d = HostDecision {
        verdict: HostVerdict::Change,
        reasons: Vec::new(),
        stop_all: Vec::new(),
        stop_disruptive: Vec::new(),
        current_system: None,
        // A machine that is being installed comes up from nothing. Saying
        // "no reboot needed" about it would be a sentence about a machine
        // that is not running yet.
        reboot_required: true,
        // An install is a whole system, never just a file (lane 3B's form).
        secrets_only: false,
        reboot_only: false,
        // An install has no way back and no way forward through a provider
        // either: the machine is not running, and what starts it afterwards
        // is the medium's own business (3A prints the sentence).
        provider_reboot: false,
        switch_only: false,
        needs_maintenance: false,
        class: class_of(host),
        canary_rank: u8::from(host.rollout.canary_class.is_none()),
        tier_rank: tier_rank(host, policy.kind),
        preconditions: Vec::new(),
        unknowns: Vec::new(),
    };

    if host.deployment == crate::manifest::Deployment::Context {
        d.stop_all.push(format!(
            "{id} is deployed as `context`: it is a vm somebody else instantiated, and this \
             tool never installs one."
        ));
        return settle(d, HostVerdict::Blocked);
    }

    let Some(install) = &host.install else {
        d.stop_all.push(format!(
            "{id} has no `install` table, so nothing says which disk this tool would be \
             allowed to destroy. A host is installed by naming its disk: `install = {{ disk = \
             {{ serial = \"…\", size_gb = … }}, layout = \"disko/…\" }}` in the inventory. \
             Until then {id} is a machine somebody else installed, and `plan --kind upgrade` \
             is how it is taken forward."
        ));
        return settle(d, HostVerdict::Blocked);
    };

    d.preconditions.push(format!(
        "{id} is installed onto the disk with the serial {} ({} GB) from a medium built for \
         this host, and onto no other",
        install.disk.serial,
        install.disk.size_bytes / 1_000_000_000
    ));
    d.preconditions.push(format!(
        "the layout {} decides the partition table, and the medium carries it",
        install.layout
    ));
    for path in &install.preserve {
        d.preconditions
            .push(format!("{path} must not be on that disk"));
    }

    match observation.host(id) {
        None => d.preconditions.push(format!(
            "the snapshot taken at {} has no entry for {id}, which is what a machine that has \
             not been installed yet looks like",
            observation.taken_at
        )),
        Some(obs) if !obs.reachable => d.preconditions.push(format!(
            "{id} did not answer when the snapshot was taken, which is what a machine that has \
             not been installed yet looks like"
        )),
        Some(obs) => {
            d.current_system = obs.current_system.clone();
            let running = obs
                .current_system
                .clone()
                .unwrap_or_else(|| "a system nobody could read".to_string());
            if policy.reinstall {
                d.preconditions.push(format!(
                    "{id} answers and runs {running}; this plan says `--reinstall`, so that \
                     machine's disk, its host key and its machine id are destroyed"
                ));
            } else {
                d.stop_all.push(format!(
                    "{id} answers and already runs {running}. Installing over it destroys that \
                     machine's data, its host key and its machine id. If that is what you \
                     mean, `plan --kind install --reinstall` says so — and the approval is \
                     bound to THAT plan's id, so this one cannot be used for it."
                ));
            }
        }
    }

    // An install never asks a group for permission: nothing of this host is
    // running, so there is no quorum to keep and no guest to move. What
    // protects the fleet here is that the disk is destroyed by a person
    // standing in front of one machine.
    let verdict = if d.stop_all.is_empty() {
        HostVerdict::Change
    } else {
        HostVerdict::Blocked
    };
    settle(d, verdict)
}

/// The steps of an install: what the plan can say about a person in front of
/// a machine.
///
/// Three, and only the middle one does anything. There is no `stage` (the
/// closure travels in the medium), no `lock` (nothing on that host could be
/// holding one), no `activate` (`nixos-install` is the activation) and no
/// `confirm` (a machine with no previous generation has nothing to fall back
/// to). `apply` refuses to carry an `install` action out at all — the
/// destruction happens at the target, by a person, through
/// `meister-install confirm` — and the plan is the sheet they work from.
fn install_specs(release: &ReleaseManifest, id: &str, decision: &HostDecision) -> Vec<StepSpec> {
    let fleet = &release.resolved_fleet;
    let host = &fleet.hosts[id];
    let desired = release.artifacts[id].toplevel.store_path.clone();
    let mut specs = vec![
        step(ActionKind::Preflight, Disruption::None)
            .maybe_from(decision.current_system.clone())
            .to(desired.clone()),
    ];
    if let Some(install) = &host.install {
        // What this step does to what is RUNNING, which on a machine nobody
        // can reach is nothing. A blank box that is about to be installed
        // interrupts no service and moves no guest, so its plan asks for
        // `destructive` and nothing else; a reinstall over a host that
        // answers interrupts everything on it, and its plan says so by
        // asking for `disruptive` as well. The disk is destroyed either
        // way, and that is the class both of them share.
        let disruption = if decision.current_system.is_some() {
            Disruption::Reboot
        } else {
            Disruption::None
        };
        specs.push(
            step(ActionKind::Install, disruption)
                .from(format!(
                    "the disk {} ({} GB)",
                    install.disk.serial,
                    install.disk.size_bytes / 1_000_000_000
                ))
                .to(desired)
                .because(format!(
                    "boot the medium `meister-deploy install --plan <p.json> --host {id}` \
                     built, and type `meister-install confirm --host {id} --disk {}` on its \
                     console",
                    install.disk.serial
                ))
                .because(format!(
                    "{id} boots {} afterwards, and the medium's last line is the host key \
                     fingerprint `meister-deploy keys enroll {id} --fingerprint …` needs",
                    host.build.boot.mode
                )),
        );
    }
    specs.push(
        step(ActionKind::Verify, Disruption::None)
            .to(host.checks.required.join(", "))
            .because(
                "after the machine has been enrolled and bootstrapped — an installed host that \
                 carries no identity yet is `unenrolled`, which is a state and never a pass",
            ),
    );
    specs
}

// --- end lane 3A ----------------------------------------------------------

/// The verdict, and the sentences behind it. An unchanged host keeps its
/// group's troubles out of its own reasons: nothing is being done to it, so
/// there is nothing for a lost quorum to forbid.
fn settle(mut d: HostDecision, verdict: HostVerdict) -> HostDecision {
    d.verdict = verdict;
    let mut reasons = d.stop_all.clone();
    if verdict != HostVerdict::Unchanged {
        reasons.extend(d.stop_disruptive.iter().cloned());
    }
    d.reasons = reasons;
    d
}

/// Which hosts are evidence for which. A class is a kernel, the profiles
/// around it and the hardware under it: a canary that survived proves
/// something about the hosts that share those and about nobody else.
fn class_of(host: &crate::manifest::ResolvedHost) -> String {
    if let Some(declared) = &host.rollout.canary_class {
        return declared.clone();
    }
    let gpus: Vec<&str> = host
        .hardware
        .gpus
        .iter()
        .map(|g| g.model.as_str())
        .collect();
    let nics: Vec<String> = host
        .hardware
        .nics
        .iter()
        .map(|n| {
            if n.rdma {
                format!("{}:rdma", n.name)
            } else {
                n.name.clone()
            }
        })
        .collect();
    let or_dash = |v: Vec<&str>| {
        if v.is_empty() {
            "-".to_string()
        } else {
            v.join("+")
        }
    };
    format!(
        "derived:{}|{}|{}|{}",
        host.build.boot.kernel_version,
        or_dash(host.profiles.iter().map(String::as_str).collect()),
        or_dash(gpus),
        or_dash(nics.iter().map(String::as_str).collect())
    )
}

// ---------------------------------------------------------------------------
// Order
// ---------------------------------------------------------------------------

/// Which tier a role belongs to. An agent takes orders from a cluster, a
/// cluster from a cloud, and both authenticate against the addons. A host is
/// placed at its HIGHEST tier, because a host with three roles is one
/// machine and one interruption.
fn tier_of_role(role: &str) -> u8 {
    match role {
        "agent" => 0,
        "cluster" => 1,
        "cloud" => 2,
        "addons" => 3,
        // A role this tool does not know goes with the agents: it is served
        // by the fleet rather than serving it, which is the safe assumption.
        _ => 0,
    }
}

fn tier_of(host: &crate::manifest::ResolvedHost) -> u8 {
    host.roles
        .iter()
        .map(|r| tier_of_role(r))
        .max()
        .unwrap_or(0)
}

/// The order this kind of plan wants the tiers in.
fn tier_rank(host: &crate::manifest::ResolvedHost, kind: PlanKind) -> u8 {
    let tier = tier_of(host);
    match kind {
        // A node goes forward before the node that gives it orders: the
        // lower tier understands the command before the upper tier gives it.
        PlanKind::Upgrade | PlanKind::Install | PlanKind::KeysRotate | PlanKind::KeysRevoke => tier,
        // The prerequisite stands before the dependant looks for it. Addons
        // first, because an identity provider is what the rest authenticates
        // against.
        PlanKind::Bootstrap | PlanKind::Retire => u8::MAX - tier,
    }
}

/// The real edges, each with the sentence that justifies it.
fn dependencies(
    fleet: &ResolvedFleet,
    selection: &[String],
    kind: PlanKind,
) -> BTreeMap<String, Vec<Dependency>> {
    let selected: BTreeSet<&String> = selection.iter().collect();
    let has_role = |id: &String, role: &str| {
        fleet
            .hosts
            .get(id)
            .map(|h| h.roles.iter().any(|r| r == role))
            .unwrap_or(false)
    };
    let mut edges: BTreeMap<String, Vec<Dependency>> = selection
        .iter()
        .map(|id| (id.clone(), Vec::new()))
        .collect();
    let bootstrap = matches!(kind, PlanKind::Bootstrap | PlanKind::Retire);

    let mut add = |dependant: &String, on: &String, reason: String| {
        // One machine with two roles is one interruption, not an edge to
        // itself.
        if dependant == on {
            return;
        }
        // An edge only ever goes from a host that comes LATER in the tier
        // order to one that comes earlier. Without this, three machines that
        // each carry the cloud and the cluster role would each wait for the
        // other two — a cycle made out of a fleet that is simply symmetric.
        // A host is placed at its highest tier and is one interruption
        // there, so two hosts of the same tier are peers with nothing to
        // order between them, and the group's own capacity is what keeps
        // them apart.
        let (Some(later), Some(earlier)) = (fleet.hosts.get(dependant), fleet.hosts.get(on)) else {
            return;
        };
        if tier_rank(later, kind) <= tier_rank(earlier, kind) {
            return;
        }
        let entry = edges.entry(dependant.clone()).or_default();
        if !entry.iter().any(|d| &d.host == on) {
            entry.push(Dependency {
                host: on.clone(),
                reason,
            });
        }
    };

    for agent in selection.iter().filter(|id| has_role(id, "agent")) {
        let Some(group) = fleet.hosts[agent].controller_group.as_ref() else {
            continue;
        };
        let Some(controllers) = fleet.groups.get(group) else {
            continue;
        };
        for controller in controllers
            .members
            .iter()
            .filter(|m| selected.contains(m) && has_role(m, "cluster"))
        {
            if bootstrap {
                add(
                    agent,
                    controller,
                    format!(
                        "{agent} registers with the cluster group {group}, so {controller} has \
                         to be there before it looks"
                    ),
                );
            } else {
                add(
                    controller,
                    agent,
                    format!(
                        "{controller} gives orders to {agent}, so the agent goes forward first \
                         and understands the command before it is given"
                    ),
                );
            }
        }
    }

    let clouds: Vec<&String> = selection
        .iter()
        .filter(|id| has_role(id, "cloud"))
        .collect();
    for cluster in selection.iter().filter(|id| has_role(id, "cluster")) {
        for cloud in &clouds {
            if bootstrap {
                add(
                    cluster,
                    cloud,
                    format!(
                        "{cluster} reports to the cloud tier, so {cloud} has to be there before \
                         it reports"
                    ),
                );
            } else {
                add(
                    cloud,
                    cluster,
                    format!(
                        "{cloud} gives orders to {cluster}, so the cluster goes forward first \
                         and understands the command before it is given"
                    ),
                );
            }
        }
    }
    edges
}

/// Kahn's algorithm with a deterministic tie-break, so the same fleet always
/// comes out in the same order — and a cycle is an error rather than a host
/// that quietly never gets a wave.
///
/// The tie-break is the rollout's own priority: the tier, then the canary
/// class, then the marked canary, then the id. The cycle check is here
/// rather than nowhere even though [`dependencies`] cannot build one today
/// (edges only ever go between different tiers): it is what makes the next
/// edge somebody adds safe.
fn topological(
    selection: &[String],
    decisions: &BTreeMap<String, HostDecision>,
    edges: &BTreeMap<String, Vec<Dependency>>,
) -> Result<Vec<String>> {
    let mut remaining: BTreeSet<String> = selection.iter().cloned().collect();
    let mut out: Vec<String> = Vec::new();

    while !remaining.is_empty() {
        let mut ready: Vec<&String> = remaining
            .iter()
            .filter(|id| {
                edges
                    .get(*id)
                    .map(|deps| deps.iter().all(|d| !remaining.contains(&d.host)))
                    .unwrap_or(true)
            })
            .collect();
        if ready.is_empty() {
            bail!(
                "the order of {} cannot be worked out: they wait for each other. A cycle in \
                 the fleet's own dependencies is a fleet this tool cannot roll out in one \
                 plan.",
                remaining.iter().cloned().collect::<Vec<_>>().join(", ")
            );
        }
        ready.sort_by_key(|id| {
            let d = &decisions[*id];
            (d.tier_rank, d.class.as_str(), d.canary_rank, id.as_str())
        });
        let next = ready[0].clone();
        remaining.remove(&next);
        out.push(next);
    }
    Ok(out)
}

/// Hand out wave numbers in the topological order, honouring every capacity
/// at once: the group's quorum, the group's `max_unavailable`, one member of
/// a raft group at a time, and one canary per class before its class.
fn assign_waves(
    fleet: &ResolvedFleet,
    order: &[String],
    decisions: &BTreeMap<String, HostDecision>,
    edges: &BTreeMap<String, Vec<Dependency>>,
    groups: &BTreeMap<String, GroupView>,
    canaries: &BTreeSet<String>,
) -> BTreeMap<String, u32> {
    let mut waves: BTreeMap<String, u32> = BTreeMap::new();
    let mut placed: BTreeMap<u32, Vec<String>> = BTreeMap::new();

    for id in order {
        let decision = &decisions[id];
        if !decision.acts() {
            // A host that changes nothing, and a host that may not be
            // touched, take no room in a wave: a wave is a rollout
            // constraint and neither of them is a rollout.
            waves.insert(id.clone(), 0);
            continue;
        }
        let mut wave = edges
            .get(id)
            .map(|deps| {
                deps.iter()
                    .filter(|d| {
                        decisions
                            .get(&d.host)
                            .map(HostDecision::acts)
                            .unwrap_or(false)
                    })
                    .filter_map(|d| waves.get(&d.host).map(|w| w + 1))
                    .max()
                    .unwrap_or(0)
            })
            .unwrap_or(0);
        // A class's canary goes alone, and the rest of the class comes after
        // it: evidence from one host is worth having before sixty follow.
        if !canaries.contains(id) {
            let after = canaries
                .iter()
                .filter(|c| decisions[*c].class == decision.class)
                .filter_map(|c| waves.get(c))
                .max();
            if let Some(w) = after {
                wave = wave.max(w + 1);
            }
        }
        while !fits(
            fleet, id, decision, canaries, wave, &placed, decisions, groups,
        ) {
            wave += 1;
        }
        waves.insert(id.clone(), wave);
        placed.entry(wave).or_default().push(id.clone());
    }
    waves
}

#[allow(clippy::too_many_arguments)]
fn fits(
    fleet: &ResolvedFleet,
    id: &str,
    decision: &HostDecision,
    canaries: &BTreeSet<String>,
    wave: u32,
    placed: &BTreeMap<u32, Vec<String>>,
    decisions: &BTreeMap<String, HostDecision>,
    groups: &BTreeMap<String, GroupView>,
) -> bool {
    let Some(here) = placed.get(&wave) else {
        return true;
    };
    // A canary shares its wave with nobody of its own class.
    if canaries.contains(id)
        && here
            .iter()
            .any(|other| decisions[other].class == decision.class)
    {
        return false;
    }
    for group in &fleet.hosts[id].groups {
        let Some(view) = groups.get(group) else {
            continue;
        };
        let already = here
            .iter()
            .filter(|other| fleet.hosts[*other].groups.iter().any(|g| g == group))
            .count() as u32;
        let room = match view.kind {
            // Strictly one at a time, whatever `max_unavailable` says: two
            // members of a raft group restarting together is the outage the
            // whole arithmetic exists to prevent.
            GroupKind::Raft => 1,
            GroupKind::Compute | GroupKind::Custom => view.allowed_unavailable.max(1),
        };
        if already + 1 > room {
            return false;
        }
    }
    true
}

// ---------------------------------------------------------------------------
// Steps
// ---------------------------------------------------------------------------

/// One step before it knows its number, its wave or what forbids it.
struct StepSpec {
    kind: ActionKind,
    current: Option<String>,
    desired: Option<String>,
    disruption: Disruption,
    preconditions: Vec<String>,
}

fn step(kind: ActionKind, disruption: Disruption) -> StepSpec {
    StepSpec {
        kind,
        current: None,
        desired: None,
        disruption,
        preconditions: Vec::new(),
    }
}

impl StepSpec {
    fn from(mut self, current: impl Into<String>) -> StepSpec {
        self.current = Some(current.into());
        self
    }

    fn maybe_from(mut self, current: Option<String>) -> StepSpec {
        self.current = current;
        self
    }

    fn to(mut self, desired: impl Into<String>) -> StepSpec {
        self.desired = Some(desired.into());
        self
    }

    fn because(mut self, why: impl Into<String>) -> StepSpec {
        self.preconditions.push(why.into());
        self
    }
}

/// The steps for one host, in the order they have to happen — and the set of
/// approvals they need between them.
#[allow(clippy::too_many_arguments)]
fn steps_for(
    release: &ReleaseManifest,
    id: &str,
    decision: &HostDecision,
    observation: &Observations,
    groups: &BTreeMap<String, GroupView>,
    edges: &BTreeMap<String, Vec<Dependency>>,
    policy: &PlanPolicy,
    wave: u32,
) -> (Vec<Action>, BTreeSet<ApprovalClass>) {
    let fleet = &release.resolved_fleet;
    let host = &fleet.hosts[id];
    let artifacts = &release.artifacts[id];
    let desired = artifacts.toplevel.store_path.clone();
    let obs = observation.host(id);

    let mut specs: Vec<StepSpec> = Vec::new();
    // --- lane 5A: a rotation is its own five steps ---
    if policy.kind == PlanKind::KeysRotate && decision.verdict == HostVerdict::Change {
        specs.push(
            step(ActionKind::Preflight, Disruption::None)
                .maybe_from(decision.current_system.clone())
                .to(desired.clone()),
        );
        specs.push(
            step(ActionKind::Lock, Disruption::None)
                .from("free")
                .to("held by this run")
                .because(
                    "D6: a key rotation holds the host for the whole run, so a second \
                     operator finds the door shut rather than a half-replaced pair",
                ),
        );
        if let Some(rotation) = policy.rotations.get(id) {
            specs.extend(rotate_specs(id, rotation));
        }
        specs.push(
            step(ActionKind::Unlock, Disruption::None)
                .from("held by this run")
                .to("free"),
        );
    } else
    // --- end lane 5A ---
    // --- lane 3A: first installation ---
    if policy.kind == PlanKind::Install {
        specs = install_specs(release, id, decision);
    } else if decision.verdict == HostVerdict::Unchanged {
        // --- end lane 3A ---
        // Two steps, and neither of them touches anything. A host that
        // already runs what the release says is not staged, not activated
        // and not handed a secret (V10).
        specs.push(
            step(ActionKind::Preflight, Disruption::None)
                .maybe_from(decision.current_system.clone())
                .to(desired.clone())
                .because(format!(
                    "{id} runs, will boot and has booted the system this release builds"
                )),
        );
        specs.push(
            step(ActionKind::Verify, Disruption::None)
                .to(host.checks.required.join(", "))
                .because("nothing was changed, so this only records that it is still right"),
        );
    } else {
        specs.push(
            step(ActionKind::Preflight, Disruption::None)
                .maybe_from(decision.current_system.clone())
                .to(desired.clone()),
        );
        specs.push(
            step(ActionKind::Lock, Disruption::None)
                .from("free")
                .to("held by this run")
                .because(
                    "D6: every host of the frozen target set is held for the whole run, so a \
                     second operator finds the door shut rather than the fleet half-moved",
                ),
        );

        // --- lane 3B: what has to be put there, and only that ----------
        //
        // One step per secret whose WANTED state and whose SEEN state
        // differ, in either kind of plan. A bootstrap is not special here:
        // what makes it a bootstrap is that everything differs, because
        // nothing is there yet.
        //
        // The comparison is `crate::pki::needs_delivery`, and its asymmetry
        // is the point. A public file — a certificate, a CA bundle, a CRL —
        // is compared by CONTENT, because the probe may hash it and the
        // operator's copy may be hashed here. A private file is compared
        // only by EXISTENCE: the probe answers `mode:… owner:…` for one, and
        // a digest of a private key would be a digest of a private key,
        // travelling into a journal and a receipt. So a `secrets.key` that
        // is there stays; replacing it does not rotate anything, it makes
        // what the cloud encrypted with it unreadable. That is `keys rotate`
        // (M5) and it is a plan of its own.
        let expected_here = policy.expected_credentials.get(id);
        for secret in &host.secret_refs {
            // --- lane 5A ---
            // A revocation plan carries ONE kind of file. A certificate that
            // happens to differ as well is a different decision, made by a
            // different verb, on a day somebody chose.
            // --- lane 5B: and a retirement is one of those plans ---
            if matches!(policy.kind, PlanKind::KeysRevoke | PlanKind::Retire)
                && secret.kind != crate::manifest::SecretKind::Crl
            {
                continue;
            }
            // --- end lane 5A/5B ---
            let seen = obs.map(|o| o.credentials.get(&secret.id));
            let want = expected_here.and_then(|e| e.get(&secret.id));
            if !crate::pki::needs_delivery(secret, want, seen.flatten()) {
                continue;
            }
            // A restart is an interruption only of something that is
            // running. In a bootstrap the units are off — they wait on a CA
            // certificate that has not arrived — and calling that step
            // disruptive would ask for an approval to interrupt nothing.
            // --- lane 5A ---
            // A revocation list is the one file in this fleet that is
            // re-read by the process that uses it, on its own clock and
            // within half a minute (`controller_api::auth::Revocations`).
            // Restarting a controller to hand it one would be the single
            // avoidable outage in the whole design, so this step interrupts
            // nothing and the executor pokes nothing.
            let restarts = secret.kind != crate::manifest::SecretKind::Crl
                && secret
                    .reload
                    .as_ref()
                    .is_some_and(|r| r.action == "restart");
            // --- end lane 5A ---
            let unit_running = secret.reload.as_ref().is_some_and(|r| {
                obs.is_some_and(|o| o.units.get(&r.unit).map(String::as_str) == Some("active"))
            });
            specs.push(
                step(
                    ActionKind::DeliverSecret,
                    if restarts && unit_running {
                        Disruption::Service
                    } else {
                        Disruption::None
                    },
                )
                .maybe_from(
                    obs.and_then(|o| o.credentials.get(&secret.id).cloned())
                        .flatten(),
                )
                .to(format!("{} at {}", secret.id, secret.target_path))
                .because(match seen.flatten() {
                    Some(None) | None => format!(
                        "{id} has no {} and the fleet says it needs one",
                        secret.target_path
                    ),
                    Some(Some(_)) => format!(
                        "what {id} has at {} is not what this repository holds for it",
                        secret.target_path
                    ),
                }),
            );
        }

        if !decision.reboot_only && !decision.secrets_only {
            specs.push(
                step(ActionKind::Stage, Disruption::None)
                    .maybe_from(decision.current_system.clone())
                    .to(desired.clone())
                    .because(
                        "the closure is copied and checked against the release before anything \
                         is switched; a stage that fails leaves the running system alone",
                    ),
            );
        }

        if decision.needs_maintenance {
            let via = policy
                .workload_control
                .as_ref()
                .map(|c| match &c.cli_profile {
                    Some(profile) => {
                        format!("`meister --config {} -p {profile}`", c.cli_config)
                    }
                    None => format!("`meister --config {}`", c.cli_config),
                })
                .unwrap_or_else(|| "the operator cli".to_string());
            specs.push(
                step(ActionKind::Cordon, Disruption::None)
                    .from("schedulable")
                    .to("cordoned")
                    .because(format!("{via} marks the node unschedulable first")),
            );
            specs.push(
                step(ActionKind::Drain, Disruption::Service)
                    .maybe_from(
                        obs.and_then(|o| o.vms_running)
                            .map(|n| format!("{n} guest(s)")),
                    )
                    .to("no guests on this host")
                    .because(
                        "a guest that cannot be moved keeps the host: the drain's own table \
                         decides that, and this step waits for its answer rather than for a \
                         timer",
                    ),
            );
        }

        if decision.secrets_only {
            // Nothing else. The system is already the one the release
            // builds; what was wrong was a file, and it has just been
            // written.
        } else if decision.reboot_only {
            if !decision.provider_reboot {
                specs.push(
                    step(ActionKind::Reboot, Disruption::Reboot)
                        .maybe_from(obs.and_then(|o| o.booted_system.clone()))
                        .to(desired.clone())
                        .because(
                            "this system was switched to and never booted, so there is nothing \
                             to activate and nothing to take back: if it does not come up, the \
                             way back is the boot menu",
                        ),
                );
            }
            // A direct-boot host gets its reboot below, after the verify: it
            // is the provider that does it, and this tool only stops there.
        } else {
            specs.push(
                step(ActionKind::Activate, Disruption::Service)
                    .maybe_from(decision.current_system.clone())
                    .to(desired.clone())
                    .because(match (
                        decision.reboot_required,
                        decision.provider_reboot,
                        decision.switch_only,
                    ) {
                        // Direct boot: the activation is the USERLAND half
                        // and runs in switch mode, because the way back a
                        // boot-mode activation needs is a boot menu and this
                        // machine has none (3A: the helper refuses it).
                        (_, true, _) => {
                            "this host boots through its provider, so the activation moves the \
                             userland at once (--mode switch) and the kernel follows when the \
                             provider loads the new bundle"
                        }
                        // --- lane 5C ---
                        // And a grub host, which reboots itself but cannot
                        // take a boot back: no `bootctl set-oneshot`, so
                        // the machine is switched now and rebooted after,
                        // and a boot that does not come up is grub's own
                        // menu and a person at a console (D5's documented
                        // limit, L2 finding N4).
                        (true, false, true) => {
                            "the boot half of this release changed and this host boots itself \
                             out of grub, which has no one-shot entry: the profile is moved at \
                             once (--mode switch) and the reboot below starts it. There is no \
                             way back from a boot that does not come up except grub's own menu"
                        }
                        // --- end lane 5C ---
                        (true, false, false) => {
                            "the boot half of this release changed, so the profile is moved and \
                             the new system takes over at the next boot (--mode boot)"
                        }
                        (false, false, _) => {
                            "nothing in the boot half changed, so this takes effect at once \
                             (--mode switch)"
                        }
                    }),
            );
            if decision.reboot_required && !decision.provider_reboot {
                specs.push(
                    step(ActionKind::Reboot, Disruption::Reboot)
                        .maybe_from(obs.and_then(|o| o.booted_system.clone()))
                        .to(desired.clone())
                        .because(
                            "the machine comes back with the same host key or this run stops: \
                             a different key is a different machine",
                        ),
                );
            }
        }

        specs.push(
            step(ActionKind::Verify, Disruption::None)
                .to(host.checks.required.join(", "))
                .because(
                    "a required check that did not pass blocks; so does one that could \
                          not tell",
                ),
        );
        if !decision.reboot_only && !decision.secrets_only {
            specs.push(
                step(ActionKind::Confirm, Disruption::None)
                    .to("the activation is kept")
                    .because(
                        "until this runs the target reverts on its own timer, which is what \
                         makes an activation survivable from a workstation that lost the link",
                    ),
            );
        }
        // --- lane 3-integration: the step this tool stops at ---------------
        //
        // LAST, and after the confirmation on purpose. The machine's own way
        // back is a timer of five minutes; arranging a provider — uploading
        // a kernel, editing a template, telling a hypervisor to restart a
        // guest — is a thing that takes as long as it takes. A halt in front
        // of an unconfirmed activation would therefore be a halt in front of
        // a machine that takes itself back while somebody works.
        //
        // The order costs one honest oddity, and the sentence below says it:
        // between the switch and the provider's reboot the host RUNS the
        // release and has BOOTED the one before it.
        if decision.provider_reboot {
            let bundle = release.artifacts[id].direct_boot.as_ref();
            specs.push(
                step(ActionKind::ProviderReboot, Disruption::Reboot)
                    .maybe_from(obs.and_then(|o| o.booted_system.clone()))
                    .to(desired.clone())
                    .because(match bundle {
                        Some(b) => format!(
                            "this tool does not reboot it: the provider has to load the kernel \
                             {}, the initrd {} and the command line {:?}, and start the machine \
                             with them",
                            b.kernel.store_path, b.initrd.store_path, b.cmdline
                        ),
                        // The host's own decision has blocked it already —
                        // `decide_host` refuses a direct host whose release
                        // carries no bundle. The step still says what is
                        // missing rather than saying nothing.
                        None => format!(
                            "this release carries no direct-boot bundle for {id}, so there is \
                             nothing a provider could be handed"
                        ),
                    })
                    .because(
                        "until that happens the host runs the new userland on the kernel it \
                         booted before, which is consistent and is not the release: the \
                         command line it is running names the previous system",
                    ),
            );
            specs.push(
                step(ActionKind::Verify, Disruption::None)
                    .to(host.checks.required.join(", "))
                    .because(
                        "and now what it booted is what it runs — the first thing this step \
                         reads is `booted_system`",
                    ),
            );
        }
        // --- end lane 3-integration ----------------------------------------
        if decision.needs_maintenance {
            specs.push(
                step(ActionKind::Uncordon, Disruption::None)
                    .from("cordoned")
                    .to("schedulable"),
            );
        }
        specs.push(
            step(ActionKind::Unlock, Disruption::None)
                .from("held by this run")
                .to("free"),
        );
    }

    // The step that actually takes the host forward is the one that carries
    // the edges; everything else on the host is ordered by the wave and by
    // the host being its own parallel group.
    let carries_edges = if policy.kind == PlanKind::Install {
        // --- lane 3A ---
        ActionKind::Install
        // --- end lane 3A ---
        // --- lane 5A ---
    } else if policy.kind == PlanKind::KeysRotate {
        ActionKind::KeysSwitch
    // --- end lane 5A ---
    } else if decision.reboot_only {
        ActionKind::Reboot
    } else {
        ActionKind::Activate
    };
    let deps = edges.get(id).cloned().unwrap_or_default();

    let mut actions = Vec::new();
    let mut needed: BTreeSet<ApprovalClass> = BTreeSet::new();
    for (index, spec) in specs.into_iter().enumerate() {
        let blocked = blocked_by(spec.kind, spec.disruption, decision);
        let classes = approval_classes(spec.kind, spec.disruption, decision, host, groups);
        if blocked.is_none() {
            needed.extend(classes.iter().copied());
        }
        let reboot_required = decision.reboot_required
            && matches!(
                spec.kind,
                ActionKind::Activate | ActionKind::Reboot | ActionKind::ProviderReboot
            );
        let mut preconditions = spec.preconditions;
        if spec.kind == ActionKind::Preflight {
            preconditions.extend(decision.preconditions.iter().cloned());
        }
        actions.push(Action {
            // Replaced by the plan once every host's steps are in one list;
            // until then it keeps the steps of this host in order.
            seq: index as u32,
            host: id.to_string(),
            kind: spec.kind,
            current: spec.current,
            desired: spec.desired,
            preconditions,
            depends_on: if spec.kind == carries_edges {
                deps.clone()
            } else {
                Vec::new()
            },
            wave,
            parallel_group: id.to_string(),
            disruption: spec.disruption,
            reboot_required,
            approval_class: classes.iter().copied().max().unwrap_or(ApprovalClass::None),
            rollback: rollback_for(spec.kind, decision, policy),
            // --- lane 3A ---
            // An install has nothing a workstation can re-check before the
            // step runs: the machine is not reachable (that is the point),
            // the fleet has no host key for it yet, and what has to still
            // be true when a partition table is destroyed — the serial, the
            // size, the layout's device, the absence of an installation
            // mark — is checked by `meister-install confirm` standing in
            // front of it. A `Reachable` condition here would be a plan
            // that contradicts its own purpose.
            validity: if policy.kind == PlanKind::Install {
                Vec::new()
            } else {
                validity_for(spec.kind, id, host, obs, artifacts, groups)
            },
            // --- end lane 3A ---
            blocked,
            // --- lane 3-integration ---
            // On the one step that is carried out somewhere else, and
            // nowhere else: every other step of this plan is something this
            // tool does itself and needs no payload to do it.
            provider_boot: if spec.kind == ActionKind::ProviderReboot {
                artifacts.direct_boot.clone()
            } else {
                None
            },
            // --- end lane 3-integration ---
        });
    }
    (actions, needed)
}

/// Which sentence forbids this step, if one does.
///
/// `preflight` and `verify` only look, and they are never forbidden: a
/// blocked host is exactly the host somebody wants a preflight to report
/// on. Everything else falls to the host's own troubles. The group's
/// troubles — a lost quorum, a membership that moved — only reach the steps
/// that interrupt something, plus the two that follow such a step and would
/// be nonsense without it.
fn blocked_by(kind: ActionKind, disruption: Disruption, decision: &HostDecision) -> Option<String> {
    if matches!(kind, ActionKind::Preflight | ActionKind::Verify) {
        return None;
    }
    if !decision.stop_all.is_empty() {
        return Some(decision.stop_all.join(" "));
    }
    // Three steps interrupt nothing themselves and are part of an
    // interruption all the same: a cordon is what makes a drain possible, an
    // uncordon takes it back, and a confirm keeps an activation. None of
    // them means anything on its own, so what forbids the interruption
    // forbids them.
    let belongs_to_a_disruption = matches!(
        kind,
        ActionKind::Cordon | ActionKind::Uncordon | ActionKind::Confirm
    );
    if (disruption != Disruption::None || belongs_to_a_disruption)
        && !decision.stop_disruptive.is_empty()
    {
        return Some(decision.stop_disruptive.join(" "));
    }
    None
}

/// Every approval this step needs. The action shows the hardest of them and
/// the plan's `approvals` is the union, so approving `singleton` never
/// quietly buys a reboot.
fn approval_classes(
    kind: ActionKind,
    disruption: Disruption,
    decision: &HostDecision,
    host: &crate::manifest::ResolvedHost,
    groups: &BTreeMap<String, GroupView>,
) -> BTreeSet<ApprovalClass> {
    let mut out = BTreeSet::new();
    if matches!(kind, ActionKind::Install | ActionKind::Revoke) {
        out.insert(ApprovalClass::Destructive);
    }
    if disruption == Disruption::None {
        return out;
    }
    out.insert(ApprovalClass::Disruptive);
    if decision.reboot_required
        && matches!(
            kind,
            ActionKind::Activate | ActionKind::Reboot | ActionKind::ProviderReboot
        )
        && host.rollout.reboot == crate::manifest::RebootPolicy::Approve
    {
        out.insert(ApprovalClass::Reboot);
    }
    for group in &host.groups {
        let Some(view) = groups.get(group) else {
            continue;
        };
        if view.kind != GroupKind::Raft {
            continue;
        }
        if view.singleton {
            // Nothing to keep a quorum with. Whatever this group serves is
            // gone while the step runs, and that is a different question
            // from "may a member go down".
            out.insert(ApprovalClass::Singleton);
        } else if view.unhealthy_now > 0 {
            // Still allowed, and this is the last margin: a member is
            // already down and this takes a second one with it.
            out.insert(ApprovalClass::Quorum);
        }
    }
    out
}

fn rollback_for(kind: ActionKind, decision: &HostDecision, policy: &PlanPolicy) -> Rollback {
    if kind != ActionKind::Activate {
        return Rollback::none();
    }
    // A machine with no boot menu has no boot-mode way back: `bootctl
    // set-oneshot` is what a boot rollback IS, and a direct-boot guest has
    // no ESP to write it into (3A measured the helper refusing it). What is
    // left is the userland half, and that is exactly what a switch takes
    // back.
    // --- lane 5C: and a grub host, for the same reason and its own ---
    if decision.provider_reboot || decision.switch_only {
        return Rollback {
            mode: RollbackMode::Switch,
            confirm_within_secs: policy.confirm_within_switch_secs,
        };
    }
    if decision.reboot_required {
        Rollback {
            mode: RollbackMode::Boot,
            confirm_within_secs: policy.confirm_within_boot_secs,
        }
    } else {
        Rollback {
            mode: RollbackMode::Switch,
            confirm_within_secs: policy.confirm_within_switch_secs,
        }
    }
}

/// What has to still be true when this step actually runs.
fn validity_for(
    kind: ActionKind,
    id: &str,
    host: &crate::manifest::ResolvedHost,
    obs: Option<&crate::observation::HostObservation>,
    artifacts: &crate::release::HostArtifacts,
    groups: &BTreeMap<String, GroupView>,
) -> Vec<Validity> {
    use ActionKind::*;
    let mut out = vec![Validity::Reachable {
        host: id.to_string(),
    }];
    if let Some(fingerprint) = &host.ssh.host_key_fingerprint {
        out.push(Validity::HostKey {
            host: id.to_string(),
            fingerprint: fingerprint.clone(),
        });
    }
    // --- lane 5A ---
    // The same two facts every changing step is validated against: it is
    // reachable, and it is the machine the fleet enrolled. A rotation adds
    // no system facts, because it changes no system.
    let wants_identity =
        matches!(kind, Preflight | DeliverSecret | Activate | Install) || kind.is_keys();
    // --- end lane 5A ---
    if wants_identity && let Some(machine_id) = obs.and_then(|o| o.identity.machine_id.clone()) {
        out.push(Validity::MachineId {
            host: id.to_string(),
            machine_id,
        });
    }
    if matches!(kind, Preflight | Activate | Install) {
        out.push(Validity::CurrentSystem {
            host: id.to_string(),
            store_path: obs.and_then(|o| o.current_system.clone()),
        });
        if let Some(generation) = obs.and_then(|o| o.generation) {
            out.push(Validity::Generation {
                host: id.to_string(),
                generation,
            });
        }
    }
    if matches!(kind, Preflight | Lock | Activate | Install) {
        out.push(Validity::NoForeignLock {
            host: id.to_string(),
        });
    }
    if matches!(kind, Preflight | Stage | Activate) {
        // V12: the bytes this plan was made for, named where the executor
        // asks about them rather than only in the plan's header.
        out.push(Validity::Artifact {
            host: id.to_string(),
            store_path: artifacts.toplevel.store_path.clone(),
            nar_hash: artifacts.toplevel.nar_hash.clone(),
        });
    }
    if matches!(kind, Cordon | Drain | Activate | Reboot | ProviderReboot) {
        for group in &host.groups {
            if let Some(view) = groups.get(group)
                && view.kind == GroupKind::Raft
                && !view.singleton
            {
                out.push(Validity::QuorumAllows {
                    group: group.clone(),
                    allowed_unavailable: view.allowed_unavailable,
                });
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// What `apply` asks immediately before it changes anything
// ---------------------------------------------------------------------------

/// The answer to "is this plan still the truth?".
///
/// Three answers and not two, because "do not do this" and "ask again" call
/// for different things from an operator. A quorum that got worse is a fleet
/// to look at; a generation that moved is a plan to make again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Proceed,
    /// Something is wrong that a new plan would not fix.
    Stop {
        reasons: Vec<String>,
    },
    /// The world moved. The same question asked again gets a usable answer.
    Replan {
        reasons: Vec<String>,
    },
}

impl Verdict {
    pub fn is_proceed(&self) -> bool {
        matches!(self, Verdict::Proceed)
    }

    pub fn reasons(&self) -> &[String] {
        match self {
            Verdict::Proceed => &[],
            Verdict::Stop { reasons } | Verdict::Replan { reasons } => reasons,
        }
    }
}

/// Re-check everything a plan assumed, against a snapshot taken just now.
///
/// This is the question `apply` asks before EVERY mutation, not once at the
/// start: between the plan and the third host of a wave there is a rollout's
/// worth of time, and a fleet does not hold still for it. Pure, like the
/// planner — `now` arrives as a value and the snapshot arrives as data.
///
/// Only the hosts the plan may actually act on are re-checked. A host the
/// plan already blocked is not re-examined: it was down when the plan was
/// made, it is down now, and stopping the whole run over a fact the plan
/// already wrote down would make every degraded fleet unrollable.
pub fn validate_against(
    plan: &DeploymentPlan,
    release: &ReleaseManifest,
    fresh: &Observations,
    now: DateTime<Utc>,
) -> Verdict {
    let mut stop: Vec<String> = Vec::new();
    let mut replan: Vec<String> = Vec::new();

    if release.release_id != plan.release_id {
        stop.push(format!(
            "this plan was made for the release {} and the release handed to it is {}. \
             A plan names the bytes it was made for; another build is another plan.",
            plan.release_id, release.release_id
        ));
        // Everything below compares against artifacts, so there is nothing
        // more to be learned from the wrong release.
        return Verdict::Stop { reasons: stop };
    }
    if now >= plan.expires_at {
        replan.push(format!(
            "this plan expired at {} and it is {now}. What it knows about the fleet is that \
             old; make it again.",
            plan.expires_at
        ));
    }
    if fresh.provisional {
        stop.push(
            "the snapshot handed to this check is provisional: nothing was asked of any host, \
             so it cannot confirm anything the plan assumed."
                .to_string(),
        );
    }

    for id in &plan.selection.targets {
        let planned = &plan.hosts[id];
        if planned.verdict.blocks() {
            continue;
        }
        // V12, at the last possible moment: the release still has to name
        // the exact bytes this plan was made for.
        match release.artifacts.get(id) {
            None => stop.push(format!(
                "the release no longer builds anything for {id}, and this plan has steps for it."
            )),
            Some(artifacts) => {
                if artifacts.toplevel.store_path != planned.desired_system {
                    stop.push(format!(
                        "this plan takes {id} to {} and the release now says {}. \
                         The build moved under the plan; make it again.",
                        planned.desired_system, artifacts.toplevel.store_path
                    ));
                } else if artifacts.toplevel.nar_hash != planned.desired_nar_hash {
                    stop.push(format!(
                        "the system built for {id} is at the same store path and hashes to {} \
                         rather than {}. Same name, different bytes: this plan is not about \
                         what is in the store.",
                        artifacts.toplevel.nar_hash, planned.desired_nar_hash
                    ));
                }
            }
        }

        let before = plan.observation.host(id);
        let Some(after) = fresh.host(id) else {
            stop.push(format!(
                "the fresh snapshot has no entry for {id}, and this plan has steps for it. \
                 A step is not taken on a host nobody just looked at."
            ));
            continue;
        };
        if !after.reachable {
            stop.push(format!(
                "{id} does not answer any more; it did when this plan was made."
            ));
            continue;
        }
        let Some(before) = before else {
            // The plan may act on it, so it saw it. If it did not, the plan
            // is not one this check can vouch for.
            stop.push(format!(
                "this plan has steps for {id} and carries no observation of it, so there is \
                 nothing to compare the fleet against."
            ));
            continue;
        };

        if before.identity.host_key_fingerprint != after.identity.host_key_fingerprint {
            stop.push(format!(
                "identity changed: {id} answered with {} when this plan was made and with {} \
                 now.",
                option(&before.identity.host_key_fingerprint),
                option(&after.identity.host_key_fingerprint)
            ));
        }
        if before.identity.machine_id != after.identity.machine_id {
            stop.push(format!(
                "{id} reports the machine id {} and reported {} when this plan was made; it is \
                 not the same installation.",
                option(&after.identity.machine_id),
                option(&before.identity.machine_id)
            ));
        }
        if before.current_system != after.current_system {
            replan.push(format!(
                "{id} now runs {} and ran {} when this plan was made; somebody deployed to it \
                 in the meantime.",
                option(&after.current_system),
                option(&before.current_system)
            ));
        }
        if before.generation != after.generation {
            replan.push(format!(
                "the system generation of {id} moved from {} to {} since this plan was made.",
                before
                    .generation
                    .map(|g| g.to_string())
                    .unwrap_or_else(|| "unknown".to_string()),
                after
                    .generation
                    .map(|g| g.to_string())
                    .unwrap_or_else(|| "unknown".to_string())
            ));
        }
        if let Some(lock) = &after.lock
            && before.lock.as_ref().map(|l| &l.run_id) != Some(&lock.run_id)
        {
            stop.push(format!(
                "the run {} has taken {id} since this plan was made (operator {}). Two runs on \
                 one host is the thing the lock exists to prevent.",
                lock.run_id, lock.operator
            ));
        }
        let new_txns: Vec<&str> = after
            .open_txns
            .iter()
            .filter(|t| !before.open_txns.iter().any(|b| b.id == t.id))
            .map(|t| t.id.as_str())
            .collect();
        if !new_txns.is_empty() {
            stop.push(format!(
                "{id} has picked up the transaction(s) {} since this plan was made; somebody \
                 else is activating something on it.",
                new_txns.join(", ")
            ));
        }
    }

    // The quorum arithmetic again, on the fresh facts and with the same
    // function — a second implementation here would be a second answer to
    // keep in step.
    let selected: BTreeSet<String> = plan.selection.targets.iter().cloned().collect();
    let (now_groups, _) = group_views(&release.resolved_fleet, fresh, &selected);
    for (id, planned) in &plan.groups {
        let Some(current) = now_groups.get(id) else {
            continue;
        };
        if planned.blocked.is_none()
            && let Some(why) = &current.blocked
        {
            stop.push(format!("{why} It could when this plan was made."));
        } else if current.allowed_unavailable < planned.allowed_unavailable {
            stop.push(format!(
                "group {id} could afford to lose {} member(s) when this plan was made and can \
                 afford {} now.",
                planned.allowed_unavailable, current.allowed_unavailable
            ));
        }
    }

    if !stop.is_empty() {
        Verdict::Stop { reasons: stop }
    } else if !replan.is_empty() {
        Verdict::Replan { reasons: replan }
    } else {
        Verdict::Proceed
    }
}

fn option(value: &Option<String>) -> String {
    value.clone().unwrap_or_else(|| "nothing".to_string())
}

/// Which approvals this plan needs and nobody has granted for THIS plan.
///
/// A grant is a class and a plan id. The id is the whole mechanism: a
/// `--approve reboot=<some other plan>` copied out of yesterday's terminal
/// approves yesterday's plan, and it is not going to be mistaken for this
/// one.
pub fn approvals_missing(
    plan: &DeploymentPlan,
    granted: &[(ApprovalClass, String)],
) -> Vec<ApprovalClass> {
    plan.approvals
        .iter()
        .map(|a| a.class)
        .filter(|class| {
            !granted
                .iter()
                .any(|(given, for_plan)| given == class && for_plan == &plan.plan_id)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{at, onebox};
    use crate::observation::{BootedKernel, Observations};

    fn ids(v: Vec<String>) -> Vec<String> {
        v
    }

    #[test]
    fn all_is_every_host_in_id_order() {
        let fleet = onebox();
        assert_eq!(ids(select(&fleet, "all").unwrap()), ["box", "n1", "n2"]);
    }

    #[test]
    fn a_comma_is_a_union_and_the_answer_is_sorted_and_unique() {
        let fleet = onebox();
        assert_eq!(
            ids(select(&fleet, "host=n2,host=box,host=n2").unwrap()),
            ["box", "n2"]
        );
    }

    #[test]
    fn every_key_selects_what_it_says() {
        let fleet = onebox();
        assert_eq!(ids(select(&fleet, "group=compute").unwrap()), ["n1", "n2"]);
        assert_eq!(ids(select(&fleet, "role=cloud").unwrap()), ["box"]);
        assert_eq!(
            ids(select(&fleet, "role=agent").unwrap()),
            ["box", "n1", "n2"]
        );
        assert_eq!(
            ids(select(&fleet, "profile=compute-cpu").unwrap()),
            ["n1", "n2"]
        );
        assert_eq!(
            ids(select(&fleet, "site=ikr-lab").unwrap()),
            ["box", "n1", "n2"]
        );
    }

    #[test]
    fn a_bang_takes_away() {
        let fleet = onebox();
        assert_eq!(ids(select(&fleet, "all,!host=box").unwrap()), ["n1", "n2"]);
        assert_eq!(
            ids(select(&fleet, "role=agent,!group=compute").unwrap()),
            ["box"]
        );
        // Whitespace around the terms is the operator's shell, not a syntax.
        assert_eq!(
            ids(select(&fleet, " all , ! host=n1 ").unwrap()),
            ["box", "n2"]
        );
    }

    #[test]
    fn an_exclusion_needs_something_to_exclude_from() {
        let fleet = onebox();
        let err = select(&fleet, "!host=box").unwrap_err().to_string();
        assert!(err.contains("nothing has been selected yet"), "{err}");
        assert!(err.contains("all,!host=box"), "{err}");
    }

    #[test]
    fn an_unknown_key_lists_the_keys_that_exist() {
        let fleet = onebox();
        let err = select(&fleet, "rack=1").unwrap_err().to_string();
        assert!(err.contains("host, group, role, profile, site"), "{err}");
    }

    #[test]
    fn an_unknown_value_lists_the_values_that_exist() {
        let fleet = onebox();
        for (expr, needle) in [
            ("group=storage", "box, compute"),
            ("role=database", "agent"),
            ("profile=gpu", "compute-cpu"),
            ("site=munich", "ikr-lab"),
        ] {
            let err = select(&fleet, expr).unwrap_err().to_string();
            assert!(err.contains(needle), "{expr}: {err}");
        }
    }

    #[test]
    fn a_host_that_is_not_in_the_release_is_an_error_and_not_an_empty_plan() {
        let fleet = onebox();
        let err = select(&fleet, "host=n9").unwrap_err().to_string();
        assert!(err.contains("has no host n9"), "{err}");
        assert!(err.contains("box, n1, n2"), "{err}");
    }

    #[test]
    fn a_partial_manifest_says_it_is_partial_instead_of_denying_the_host() {
        let mut fleet = onebox();
        fleet.hosts.remove("n2");
        fleet.partial = true;
        fleet.evaluated_hosts = vec!["box".to_string(), "n1".to_string()];
        let err = select(&fleet, "host=n2").unwrap_err().to_string();
        assert!(err.contains("resolved with --hosts"), "{err}");
        assert!(err.contains("knows nothing about n2"), "{err}");
    }

    #[test]
    fn a_selector_that_ends_up_empty_is_an_error() {
        let fleet = onebox();
        let err = select(&fleet, "all,!all").unwrap_err().to_string();
        assert!(err.contains("selects no host"), "{err}");
        let err = select(&fleet, "").unwrap_err().to_string();
        assert!(err.contains("empty selector"), "{err}");
        let err = select(&fleet, "all,,host=n1").unwrap_err().to_string();
        assert!(err.contains("empty term"), "{err}");
        let err = select(&fleet, "all,!").unwrap_err().to_string();
        assert!(err.contains("with nothing after it"), "{err}");
    }

    #[test]
    fn a_term_without_an_equals_sign_says_what_a_term_looks_like() {
        let fleet = onebox();
        let err = select(&fleet, "box").unwrap_err().to_string();
        assert!(err.contains("is not a selector"), "{err}");
        let err = select(&fleet, "host=").unwrap_err().to_string();
        assert!(err.contains("no value after"), "{err}");
    }

    // -----------------------------------------------------------------
    // The planner, host by host
    // -----------------------------------------------------------------

    use crate::fixtures::{
        expected_credentials, observed, onebox_enrolled, plan_policy,
        plan_policy_with_certificates, release_of, with_new_systems,
    };
    use crate::observation::{Lock, Txn, TxnState};

    const NOW: &str = "2026-09-21T12:00:00Z";
    const TAKEN: &str = "2026-09-21T11:59:00Z";

    /// Everything the fleet already runs, and a release that changes `hosts`.
    fn upgrade(hosts: &[&str], new_kernel: bool) -> (ReleaseManifest, Observations) {
        let base = onebox_enrolled();
        let running = release_of(base.clone());
        let observation = observed(&running, at(TAKEN));
        let release = with_new_systems(base, hosts, new_kernel);
        (release, observation)
    }

    fn planned(
        release: &ReleaseManifest,
        expr: &str,
        observation: &Observations,
    ) -> DeploymentPlan {
        plan(
            release,
            expr,
            observation,
            None,
            &plan_policy(PlanKind::Upgrade),
            at(NOW),
        )
        .expect("this fixture plans")
    }

    fn kinds(plan: &DeploymentPlan, host: &str) -> Vec<ActionKind> {
        plan.actions_for(host).iter().map(|a| a.kind).collect()
    }

    fn action<'a>(plan: &'a DeploymentPlan, host: &str, kind: ActionKind) -> &'a Action {
        plan.actions_for(host)
            .into_iter()
            .find(|a| a.kind == kind)
            .unwrap_or_else(|| panic!("{host} has no {kind} in this plan"))
    }

    // --- lane 3B: deliver-secret out of wanted against seen -----------

    /// A fleet nobody has bootstrapped: nothing is on any host, everything
    /// has been issued here. Every deliverable secret is delivered, in tier
    /// order, before the system that reads it is activated — and the key
    /// the target made itself never travels.
    #[test]
    fn a_bootstrap_delivers_what_the_hosts_have_not_got_and_nothing_else() {
        let base = onebox_enrolled();
        let running = release_of(base.clone());
        let mut observation = observed(&running, at(TAKEN));
        for host in observation.hosts.values_mut() {
            host.enrolled = false;
            host.credentials.values_mut().for_each(|v| *v = None);
            // Before a bootstrap the units wait on a CA certificate that
            // has not arrived.
            host.units
                .values_mut()
                .for_each(|v| *v = "inactive".to_string());
        }
        let release = with_new_systems(base, &["box", "n1", "n2"], false);
        let policy = plan_policy_with_certificates(PlanKind::Bootstrap, &release.resolved_fleet);
        let plan = plan(&release, "all", &observation, None, &policy, at(NOW)).unwrap();

        for id in ["box", "n1", "n2"] {
            let host = &release.resolved_fleet.hosts[id];
            let delivered: Vec<&str> = plan
                .actions_for(id)
                .into_iter()
                .filter(|a| a.kind == ActionKind::DeliverSecret)
                .filter_map(|a| a.desired.as_deref())
                .collect();
            let travelling = host
                .secret_refs
                .iter()
                .filter(|s| s.source.kind != crate::manifest::SecretSourceKind::TargetGenerated)
                .count();
            assert_eq!(delivered.len(), travelling, "{id}: {delivered:?}");
            // The key the host made itself is not among them, whatever else
            // is: delivering one would mean this workstation had it.
            assert!(
                !delivered.iter().any(|d| d.starts_with("identity ")),
                "{id}: {delivered:?}"
            );
            let steps = kinds(&plan, id);
            let last_deliver = steps
                .iter()
                .rposition(|k| *k == ActionKind::DeliverSecret)
                .expect("a bootstrap delivers");
            let activate = steps
                .iter()
                .position(|k| *k == ActionKind::Activate)
                .expect("and activates afterwards");
            assert!(last_deliver < activate, "{id}: {steps:?}");
            // Writing a file is not interrupting anything, and the units
            // are not running yet.
            for action in plan
                .actions_for(id)
                .into_iter()
                .filter(|a| a.kind == ActionKind::DeliverSecret)
            {
                assert_eq!(action.disruption, Disruption::None, "{id}: {action:?}");
                assert_eq!(
                    action.approval_class,
                    ApprovalClass::None,
                    "{id}: {action:?}"
                );
                assert!(action.blocked.is_none(), "{id}: {action:?}");
            }
        }
        // Tier order: the thing that is talked TO comes first in a
        // bootstrap.
        assert!(plan.hosts["box"].wave < plan.hosts["n1"].wave);
    }

    /// The same fleet, already running: the wanted state and the seen state
    /// agree, so nothing is delivered at all.
    #[test]
    fn a_fleet_that_already_has_its_certificates_is_handed_nothing() {
        let base = onebox_enrolled();
        let running = release_of(base.clone());
        let observation = observed(&running, at(TAKEN));
        let release = with_new_systems(base, &["n1"], false);
        let policy = plan_policy_with_certificates(PlanKind::Upgrade, &release.resolved_fleet);
        let plan = plan(&release, "all", &observation, None, &policy, at(NOW)).unwrap();
        assert!(
            !plan
                .actions
                .iter()
                .any(|a| a.kind == ActionKind::DeliverSecret),
            "{:?}",
            plan.actions
                .iter()
                .filter(|a| a.kind == ActionKind::DeliverSecret)
                .collect::<Vec<_>>()
        );
    }

    /// One CA certificate was renewed on the workstation. Exactly one step
    /// per host, in an ordinary upgrade, and nothing else moves.
    #[test]
    fn a_changed_certificate_is_one_step_per_host_in_an_upgrade() {
        let base = onebox_enrolled();
        let running = release_of(base.clone());
        let observation = observed(&running, at(TAKEN));
        let release = with_new_systems(base, &["n1"], false);
        let mut expected = expected_credentials(&release.resolved_fleet);
        for secrets in expected.values_mut() {
            if let Some(value) = secrets.get_mut("ca-bundle") {
                *value = "sha256:a-new-certificate-authority".to_string();
            }
        }
        let policy = plan_policy(PlanKind::Upgrade).with_expected_credentials(expected);
        let plan = plan(&release, "all", &observation, None, &policy, at(NOW)).unwrap();

        for id in ["box", "n1", "n2"] {
            let delivered: Vec<&str> = plan
                .actions_for(id)
                .into_iter()
                .filter(|a| a.kind == ActionKind::DeliverSecret)
                .filter_map(|a| a.desired.as_deref())
                .collect();
            assert_eq!(delivered.len(), 1, "{id}: {delivered:?}");
            assert!(delivered[0].starts_with("ca-bundle "), "{delivered:?}");
        }
        // Even a host whose system does not change is handed the new
        // certificate — and it stops being `unchanged`, because something
        // has to happen to it. What happens is exactly that: no stage, no
        // activate, no confirm, nothing rebooted. Activating a system the
        // host already runs would take its lock and move its profile for a
        // file.
        assert_eq!(plan.hosts["n2"].verdict, HostVerdict::Change);
        assert_eq!(
            kinds(&plan, "n2"),
            [
                ActionKind::Preflight,
                ActionKind::Lock,
                ActionKind::DeliverSecret,
                ActionKind::Verify,
                ActionKind::Unlock
            ]
        );
        assert!(!plan.hosts["n2"].reboot_required);
        // Writing a file interrupts nothing, so none of n2's own steps asks
        // anybody for anything. (The plan as a whole needs `disruptive`,
        // because n1's system really does change.)
        for step in plan.actions_for("n2") {
            assert_eq!(step.approval_class, ApprovalClass::None, "{step:?}");
            assert_eq!(step.disruption, Disruption::None, "{step:?}");
        }
        let why = &plan.hosts["n2"].reasons;
        assert!(why.is_empty(), "nothing is in the way: {why:?}");
        let said: String = plan
            .actions_for("n2")
            .into_iter()
            .flat_map(|a| a.preconditions.clone())
            .collect::<Vec<_>>()
            .join(" ");
        assert!(
            said.contains("nothing is staged and nothing is activated"),
            "{said}"
        );
    }

    /// A restart of a unit that IS running interrupts a service; the same
    /// step in a bootstrap, where the unit waits on the file being
    /// delivered, interrupts nothing.
    #[test]
    fn a_restart_is_an_interruption_only_of_something_that_runs() {
        let base = onebox_enrolled();
        let running = release_of(base.clone());
        let mut observation = observed(&running, at(TAKEN));
        observation
            .hosts
            .get_mut("n1")
            .unwrap()
            .credentials
            .insert("ca-bundle".to_string(), None);
        let release = with_new_systems(base, &["n1"], false);
        let policy = plan_policy_with_certificates(PlanKind::Upgrade, &release.resolved_fleet);
        let plan = plan(&release, "host=n1", &observation, None, &policy, at(NOW)).unwrap();
        let deliver = action(&plan, "n1", ActionKind::DeliverSecret);
        // The fixture's ca-bundle has no reload at all, so nothing is
        // poked and nothing is interrupted.
        assert_eq!(deliver.disruption, Disruption::None, "{deliver:?}");
    }

    /// A private file that is there stays there. A `secrets.key` is the key
    /// the cloud encrypted with; replacing it does not rotate anything.
    #[test]
    fn a_secret_the_host_already_holds_is_never_replaced() {
        let base = onebox_enrolled();
        let running = release_of(base.clone());
        let observation = observed(&running, at(TAKEN));
        let release = with_new_systems(base, &["box"], false);
        // The operator has a copy and it is a different file. It changes
        // nothing: what is on the host is what was encrypted with.
        let mut expected = expected_credentials(&release.resolved_fleet);
        expected
            .get_mut("box")
            .unwrap()
            .insert("serving".to_string(), crate::pki::PRESENT.to_string());
        let policy = plan_policy(PlanKind::Upgrade).with_expected_credentials(expected);
        let held = plan(&release, "host=box", &observation, None, &policy, at(NOW)).unwrap();
        assert!(
            !kinds(&held, "box").contains(&ActionKind::DeliverSecret),
            "{:?}",
            kinds(&held, "box")
        );

        // And when it is NOT there, it is delivered — that is the one case.
        let mut fresh = observation.clone();
        fresh
            .hosts
            .get_mut("box")
            .unwrap()
            .credentials
            .insert("serving".to_string(), None);
        let missing = plan(&release, "host=box", &fresh, None, &policy, at(NOW)).unwrap();
        assert!(kinds(&missing, "box").contains(&ActionKind::DeliverSecret));
    }

    /// A bootstrap that cannot deliver is a bootstrap that would leave the
    /// host half made, and it says which verb was never run.
    #[test]
    fn a_bootstrap_without_an_issued_certificate_is_blocked_and_names_the_verb() {
        let base = onebox_enrolled();
        let running = release_of(base.clone());
        let mut observation = observed(&running, at(TAKEN));
        for host in observation.hosts.values_mut() {
            host.enrolled = false;
            host.credentials.values_mut().for_each(|v| *v = None);
        }
        let release = with_new_systems(base, &["box"], false);
        // Nothing issued at all.
        let plan = plan(
            &release,
            "host=box",
            &observation,
            None,
            &plan_policy(PlanKind::Bootstrap),
            at(NOW),
        )
        .unwrap();
        assert_eq!(plan.hosts["box"].verdict, HostVerdict::Blocked);
        let why = plan.hosts["box"].reasons.join(" ");
        assert!(why.contains("keys csr --host box"), "{why}");
        assert!(why.contains("keys issue --host box"), "{why}");
        assert!(
            why.contains("ca_dir"),
            "the operator file is named too: {why}"
        );

        // An UPGRADE of a running host is not blocked by the same absence:
        // the fleet is up, and a certificate this tool was never shown is
        // not a reason to refuse to roll it forward.
        let observation = observed(&running, at(TAKEN));
        let upgrade = planned(&release, "host=box", &observation);
        assert_eq!(upgrade.hosts["box"].verdict, HostVerdict::Change);
    }

    // --- lane 3B: the new field of the contract -----------------------

    /// A new field of the plan is a new field of the `plan_id` and a new
    /// field of the round trip, or it is a field that quietly does nothing.
    #[test]
    fn what_the_operator_had_on_disk_travels_in_the_plan_and_is_part_of_its_id() {
        let (release, observation) = upgrade(&["n1"], false);
        let bare = planned(&release, "all", &observation);
        assert!(bare.expected_credentials.is_empty());

        let mut expected: BTreeMap<String, crate::pki::ExpectedCredentials> = BTreeMap::new();
        expected.insert(
            "n1".to_string(),
            BTreeMap::from([("ca-bundle".to_string(), "sha256:aaaa".to_string())]),
        );
        // And a host nobody selected, to see it stay out.
        expected.insert(
            "nobody".to_string(),
            BTreeMap::from([("ca-bundle".to_string(), "sha256:bbbb".to_string())]),
        );
        let policy = plan_policy(PlanKind::Upgrade).with_expected_credentials(expected);
        let with = plan(&release, "all", &observation, None, &policy, at(NOW))
            .expect("this fixture plans");

        assert_eq!(
            with.expected_credentials.keys().collect::<Vec<_>>(),
            vec!["n1"],
            "a host outside the selection is not in the plan"
        );
        assert_ne!(
            with.plan_id, bare.plan_id,
            "a different thing on the operator's disk is a different plan"
        );

        // It reads back, it still hashes to its id, and the field survives.
        let text = String::from_utf8(with.to_json().unwrap()).unwrap();
        let back = DeploymentPlan::from_json(&text, "the round trip").unwrap();
        assert_eq!(back, with);
        assert_eq!(back.expected_credentials["n1"]["ca-bundle"], "sha256:aaaa");
        assert!(back.id_matches().unwrap());
    }

    // -----------------------------------------------------------------
    // lane 3A: first installation
    // -----------------------------------------------------------------

    // --- lane 5A: the rotation plan -----------------------------------

    /// A host with a certificate beside its key, and a rotation prepared
    /// for it.
    fn rotating() -> (ReleaseManifest, Observations, KeyRotation) {
        let fleet = crate::fixtures::with_cert(onebox_enrolled(), &["box"], "identity");
        let release = release_of(fleet);
        let observation = observed(&release, at(TAKEN));
        let rotation =
            crate::fixtures::rotation_for(&release.resolved_fleet, "box", "sha256:the-new-one");
        (release, observation, rotation)
    }

    /// The five phases, in order, and only one of them interrupts anything.
    #[test]
    fn a_rotation_is_five_steps_and_one_interruption() {
        let (release, observation, rotation) = rotating();
        let policy = plan_policy(PlanKind::KeysRotate).with_rotations(
            [("box".to_string(), rotation.clone())]
                .into_iter()
                .collect(),
        );
        let plan = plan(&release, "host=box", &observation, None, &policy, at(NOW))
            .expect("a rotation plans");

        assert_eq!(
            kinds(&plan, "box"),
            vec![
                ActionKind::Preflight,
                ActionKind::Lock,
                ActionKind::KeysPrepare,
                ActionKind::KeysOverlap,
                ActionKind::KeysSwitch,
                ActionKind::KeysVerify,
                ActionKind::KeysRemove,
                ActionKind::Unlock,
            ]
        );
        for action in plan.actions.iter().filter(|a| a.kind.is_keys()) {
            // Only the switch interrupts anything, and the class it asks
            // for is the one the HOST's situation deserves: `box` is a raft
            // group of one, so restarting what reads the pair takes the
            // whole control plane away for a moment and the plan says
            // `singleton` rather than `disruptive`. The four other phases
            // interrupt nothing and ask nobody.
            let expected = if action.kind == ActionKind::KeysSwitch {
                (Disruption::Service, ApprovalClass::Singleton)
            } else {
                (Disruption::None, ApprovalClass::None)
            };
            assert_eq!(
                (action.disruption, action.approval_class),
                expected,
                "{:?}",
                action.kind
            );
        }
        assert!(
            plan.approvals
                .iter()
                .any(|a| a.class == ApprovalClass::Disruptive),
            "the union of what is needed still names the interruption: {:?}",
            plan.approvals
        );
        // Nothing of a rollout, and no reboot class: a rotation replaces two
        // files.
        assert!(!plan.hosts["box"].reboot_required);
        assert!(
            !plan
                .actions
                .iter()
                .any(|a| matches!(a.kind, ActionKind::Stage | ActionKind::Activate)),
        );
        // The rotation travels IN the plan, and is therefore part of its id.
        assert_eq!(plan.rotations["box"], rotation);
        let back = DeploymentPlan::from_json(
            &String::from_utf8(plan.to_json().unwrap()).unwrap(),
            "the plan",
        )
        .expect("a rotation plan reads back");
        assert_eq!(back.rotations, plan.rotations);
        let mut edited = plan.clone();
        edited.rotations.get_mut("box").unwrap().public_key_sha256 = "ff".repeat(32);
        assert!(
            !edited.id_matches().unwrap(),
            "the rotation is not part of the plan id"
        );
    }

    /// A plan without a prepared key is not a plan that makes one.
    #[test]
    fn a_rotation_without_a_prepared_key_is_blocked_and_names_the_verb() {
        let (release, observation, _) = rotating();
        let policy = plan_policy(PlanKind::KeysRotate);
        let plan = plan(&release, "host=box", &observation, None, &policy, at(NOW)).expect("plans");
        assert_eq!(plan.hosts["box"].verdict, HostVerdict::Blocked);
        let why = plan.hosts["box"].reasons.join(" ");
        assert!(why.contains("keys rotate --host box"), "{why}");
    }

    /// The other half of the same promise, and the one an operator relies
    /// on every day: an ordinary upgrade of the same fleet rotates nothing.
    #[test]
    fn an_ordinary_plan_of_the_same_fleet_rotates_nothing() {
        let base = crate::fixtures::with_cert(onebox_enrolled(), &["box"], "identity");
        let running = release_of(base.clone());
        let observation = observed(&running, at(TAKEN));
        let release = with_new_systems(base, &["box"], true);
        for kind in [PlanKind::Upgrade, PlanKind::Bootstrap] {
            let policy = plan_policy_with_certificates(kind, &release.resolved_fleet);
            let plan = plan(&release, "all", &observation, None, &policy, at(NOW)).expect("plans");
            assert!(
                !plan.actions.iter().any(|a| a.kind.is_keys()),
                "{kind} carried a key rotation"
            );
            assert!(plan.rotations.is_empty(), "{kind}: {:?}", plan.rotations);
            let text = String::from_utf8(plan.to_json().unwrap()).unwrap();
            assert!(!text.contains("rotations"), "{kind}: {text}");
        }
    }

    /// A rotation of a host that has no identity of its own is a bootstrap
    /// somebody spelled wrong.
    #[test]
    fn a_host_without_an_identity_has_nothing_to_rotate() {
        let (release, mut observation, rotation) = rotating();
        observation.hosts.get_mut("box").unwrap().enrolled = false;
        let policy = plan_policy(PlanKind::KeysRotate)
            .with_rotations([("box".to_string(), rotation)].into_iter().collect());
        let plan = plan(&release, "host=box", &observation, None, &policy, at(NOW)).expect("plans");
        assert_eq!(plan.hosts["box"].verdict, HostVerdict::Unenrolled);
        let why = plan.hosts["box"].reasons.join(" ");
        assert!(why.contains("--kind bootstrap"), "{why}");
    }

    // --- lane 5A: the revocation plan ---------------------------------

    /// A fleet whose controller host reads a revocation list, and a snapshot
    /// in which it holds the one it was given.
    fn revoking() -> (ReleaseManifest, Observations) {
        let fleet = crate::fixtures::with_crl(onebox_enrolled(), &["box"]);
        let release = release_of(fleet);
        let observation = observed(&release, at(TAKEN));
        (release, observation)
    }

    /// What a new list does to a fleet: one file, on the hosts that read
    /// one, and nothing else happens to any of them.
    #[test]
    fn a_revocation_carries_one_file_and_interrupts_nothing() {
        let (release, observation) = revoking();
        let fleet = &release.resolved_fleet;
        // The operator has a NEW list; everything else is as the hosts have
        // it.
        let mut expected = crate::fixtures::expected_credentials(fleet);
        for secrets in expected.values_mut() {
            for (id, value) in secrets.iter_mut() {
                if id.starts_with("crl-") {
                    *value = "sha256:the-new-list".to_string();
                }
            }
        }
        let policy = plan_policy(PlanKind::KeysRevoke).with_expected_credentials(expected);
        let plan = plan(&release, "all", &observation, None, &policy, at(NOW)).expect("plans");

        assert_eq!(
            kinds(&plan, "box"),
            vec![
                ActionKind::Preflight,
                ActionKind::Lock,
                ActionKind::DeliverSecret,
                ActionKind::DeliverSecret,
                ActionKind::Verify,
                ActionKind::Unlock,
            ],
            "a revocation is preflight, the lock, the file(s), a verify and the lock back"
        );
        // Two references to ONE file (a cloud and a cluster on one host),
        // which is what the one derivation writes — and both of them the
        // list.
        for action in plan
            .actions
            .iter()
            .filter(|a| a.kind == ActionKind::DeliverSecret)
        {
            let said = action.desired.clone().unwrap_or_default();
            assert!(said.contains("crl.pem"), "{said}");
            assert_eq!(
                action.disruption,
                Disruption::None,
                "a list is re-read by the process that uses it; nothing is restarted"
            );
            assert_eq!(action.approval_class, ApprovalClass::None);
        }
        assert!(
            plan.approvals.is_empty(),
            "nothing about a revocation needs a person to be asked: {:?}",
            plan.approvals
        );
        // And the hosts that read no list are left entirely alone. The
        // sentence travels on the one step such a host has.
        for id in ["n1", "n2"] {
            assert_eq!(plan.hosts[id].verdict, HostVerdict::Unchanged, "{id}");
            let why = action(&plan, id, ActionKind::Preflight)
                .preconditions
                .join(" ");
            assert!(why.contains("reads no revocation list"), "{id}: {why}");
        }
        // Nothing of the rollout: no stage, no activation, no reboot,
        // anywhere in the plan.
        for action in &plan.actions {
            assert!(
                !matches!(
                    action.kind,
                    ActionKind::Stage
                        | ActionKind::Activate
                        | ActionKind::Reboot
                        | ActionKind::Confirm
                ),
                "{:?} has no business in a revocation",
                action.kind
            );
        }
    }

    // --- lane 5B: retiring a host --------------------------------------

    /// A retirement is a revocation that leaves the machine out.
    ///
    /// Two things have to be true and they are the whole of V25's first
    /// half: the host that is going is not in the plan at all, and what the
    /// rest of the fleet gets is the list and nothing else.
    #[test]
    fn a_retirement_carries_the_list_to_the_others_and_never_touches_the_host() {
        let fleet = crate::fixtures::with_crl(onebox_enrolled(), &["box", "n1"]);
        let release = release_of(fleet);
        let observation = observed(&release, at(TAKEN));
        let mut expected = crate::fixtures::expected_credentials(&release.resolved_fleet);
        for secrets in expected.values_mut() {
            for (id, value) in secrets.iter_mut() {
                if id.starts_with("crl-") {
                    *value = "sha256:the-list-without-n2".to_string();
                }
            }
        }
        let policy = plan_policy(PlanKind::Retire).with_expected_credentials(expected);
        // This is the selector `retire n2` writes.
        let plan = plan(
            &release,
            "all,!host=n2",
            &observation,
            None,
            &policy,
            at(NOW),
        )
        .expect("plans");

        assert_eq!(plan.kind, PlanKind::Retire);
        assert!(
            !plan.hosts.contains_key("n2"),
            "the host being retired is not in its own retirement plan: {:?}",
            plan.hosts.keys().collect::<Vec<_>>()
        );
        assert!(
            plan.actions.iter().all(|a| a.host != "n2"),
            "nothing is done to n2"
        );
        assert_eq!(
            kinds(&plan, "box"),
            vec![
                ActionKind::Preflight,
                ActionKind::Lock,
                ActionKind::DeliverSecret,
                ActionKind::DeliverSecret,
                ActionKind::Verify,
                ActionKind::Unlock,
            ],
            "the same shape a revocation has: the list, and nothing else"
        );
        for action in plan
            .actions
            .iter()
            .filter(|a| a.kind == ActionKind::DeliverSecret)
        {
            let said = action.desired.clone().unwrap_or_default();
            assert!(said.contains("crl.pem"), "{said}");
            assert_eq!(action.disruption, Disruption::None);
        }
        // Nothing of the rollout, and nothing that removes anything.
        for action in &plan.actions {
            assert!(
                !matches!(
                    action.kind,
                    ActionKind::Stage
                        | ActionKind::Activate
                        | ActionKind::Reboot
                        | ActionKind::Confirm
                ),
                "{:?} has no business in a retirement",
                action.kind
            );
        }
        assert!(plan.approvals.is_empty(), "{:?}", plan.approvals);
    }

    // --- end lane 5B ----------------------------------------------------

    /// A host that already holds this list is not written to twice.
    #[test]
    fn a_host_that_already_holds_the_list_is_unchanged() {
        let (release, observation) = revoking();
        let policy = plan_policy_with_certificates(PlanKind::KeysRevoke, &release.resolved_fleet);
        let plan = plan(&release, "all", &observation, None, &policy, at(NOW)).expect("plans");
        assert_eq!(plan.hosts["box"].verdict, HostVerdict::Unchanged);
        assert!(
            !plan
                .actions
                .iter()
                .any(|a| a.kind == ActionKind::DeliverSecret),
            "nothing to deliver"
        );
    }

    /// The honest half of V24: a revocation is in force where it arrived,
    /// and the plan says who has not got it.
    #[test]
    fn a_host_that_did_not_answer_stays_in_the_plan_and_is_named() {
        let (release, mut observation) = revoking();
        observation
            .hosts
            .get_mut("box")
            .expect("in the fixture")
            .reachable = false;
        let mut expected = crate::fixtures::expected_credentials(&release.resolved_fleet);
        for secrets in expected.values_mut() {
            for (id, value) in secrets.iter_mut() {
                if id.starts_with("crl-") {
                    *value = "sha256:the-new-list".to_string();
                }
            }
        }
        let policy = plan_policy(PlanKind::KeysRevoke).with_expected_credentials(expected);
        let plan = plan(&release, "all", &observation, None, &policy, at(NOW)).expect("plans");
        assert_eq!(plan.hosts["box"].verdict, HostVerdict::Unreachable);
        assert!(
            plan.selection
                .required_unreachable
                .contains(&"box".to_string()),
            "{:?}",
            plan.selection.required_unreachable
        );
        let why = plan.hosts["box"].reasons.join(" ");
        assert!(why.contains("still serving whatever list it had"), "{why}");
    }

    /// A list this workstation does not have is not a plan that pretends to
    /// deliver one.
    #[test]
    fn a_revocation_without_a_list_on_this_workstation_is_blocked() {
        let (release, observation) = revoking();
        let mut expected = crate::fixtures::expected_credentials(&release.resolved_fleet);
        for secrets in expected.values_mut() {
            secrets.retain(|id, _| !id.starts_with("crl-"));
        }
        let policy = plan_policy(PlanKind::KeysRevoke).with_expected_credentials(expected);
        let plan = plan(&release, "all", &observation, None, &policy, at(NOW)).expect("plans");
        assert_eq!(plan.hosts["box"].verdict, HostVerdict::Blocked);
        let why = plan.hosts["box"].reasons.join(" ");
        assert!(why.contains("keys revoke"), "{why}");
    }

    /// And a revocation never turns into a rollout: the same fleet with a
    /// system to take forward still only gets the file.
    #[test]
    fn a_host_that_also_owes_a_system_still_only_gets_the_list() {
        let base = crate::fixtures::with_crl(onebox_enrolled(), &["box"]);
        let running = release_of(base.clone());
        let observation = observed(&running, at(TAKEN));
        // A new system for the same host, which an upgrade would act on.
        let release = with_new_systems(base, &["box"], true);
        let mut expected = crate::fixtures::expected_credentials(&release.resolved_fleet);
        for secrets in expected.values_mut() {
            for (id, value) in secrets.iter_mut() {
                if id.starts_with("crl-") {
                    *value = "sha256:the-new-list".to_string();
                }
            }
        }
        let policy = plan_policy(PlanKind::KeysRevoke).with_expected_credentials(expected);
        let plan = plan(&release, "all", &observation, None, &policy, at(NOW)).expect("plans");
        assert_eq!(
            kinds(&plan, "box"),
            vec![
                ActionKind::Preflight,
                ActionKind::Lock,
                ActionKind::DeliverSecret,
                ActionKind::DeliverSecret,
                ActionKind::Verify,
                ActionKind::Unlock,
            ]
        );
        assert!(!plan.hosts["box"].reboot_required);
    }

    // --- end lane 5A ---------------------------------------------------

    /// A fleet nobody has ever reached: no host answered when the snapshot
    /// was taken, which is what a rack of new machines looks like.
    fn nothing_installed_yet() -> (ReleaseManifest, Observations) {
        let release = release_of(onebox_enrolled());
        let mut observation = observed(&release, at(TAKEN));
        for host in observation.hosts.values_mut() {
            host.reachable = false;
            host.current_system = None;
            host.booted_system = None;
            host.next_boot_system = None;
        }
        (release, observation)
    }

    fn install_plan(
        release: &ReleaseManifest,
        expr: &str,
        observation: &Observations,
        reinstall: bool,
    ) -> DeploymentPlan {
        plan(
            release,
            expr,
            observation,
            None,
            &plan_policy(PlanKind::Install).with_reinstall(reinstall),
            at(NOW),
        )
        .expect("an install plans")
    }

    #[test]
    fn a_machine_nobody_can_reach_is_exactly_what_an_install_is_for() {
        let (release, observation) = nothing_installed_yet();
        let plan = install_plan(&release, "host=n1", &observation, false);

        assert_eq!(plan.kind, PlanKind::Install);
        assert!(!plan.reinstall);
        assert_eq!(plan.hosts["n1"].verdict, HostVerdict::Change);
        assert_eq!(
            kinds(&plan, "n1"),
            [
                ActionKind::Preflight,
                ActionKind::Install,
                ActionKind::Verify
            ]
        );

        let install = action(&plan, "n1", ActionKind::Install);
        assert_eq!(install.approval_class, ApprovalClass::Destructive);
        // Nothing is running on a machine nobody can reach, so nothing is
        // interrupted: the one question is whether the disk may go.
        assert_eq!(install.disruption, Disruption::None);
        assert!(!install.is_blocked());
        // The payload a person works from: which disk, how big, which
        // system, which command.
        assert!(
            install
                .current
                .as_deref()
                .unwrap()
                .contains("S6PENX0T123457")
        );
        assert!(
            install
                .desired
                .as_deref()
                .unwrap()
                .contains("nixos-system-n1")
        );
        let said = install.preconditions.join(" ");
        assert!(
            said.contains("meister-install confirm --host n1 --disk S6PENX0T123457"),
            "{said}"
        );
        assert!(said.contains("keys enroll n1"), "{said}");

        // Nothing this workstation could re-check just before a disk on the
        // other side of a room is formatted.
        assert!(install.validity.is_empty(), "{:?}", install.validity);
        assert_eq!(install.rollback.mode, RollbackMode::None);

        // …and the plan asks for the one approval that means "destroy".
        assert_eq!(
            plan.approvals.iter().map(|a| a.class).collect::<Vec<_>>(),
            [ApprovalClass::Destructive]
        );
    }

    #[test]
    fn a_host_that_answers_is_not_installed_over_by_accident() {
        // Everything is running: an ordinary fleet, planned as an install.
        let release = release_of(onebox_enrolled());
        let observation = observed(&release, at(TAKEN));
        let plan = install_plan(&release, "host=n1", &observation, false);

        assert_eq!(plan.hosts["n1"].verdict, HostVerdict::Blocked);
        let why = plan.hosts["n1"].reasons.join(" ");
        assert!(why.contains("already runs"), "{why}");
        assert!(why.contains("--reinstall"), "{why}");
        assert!(action(&plan, "n1", ActionKind::Install).is_blocked());

        // With the word said out loud it is not blocked any more…
        let deliberate = install_plan(&release, "host=n1", &observation, true);
        assert_eq!(deliberate.hosts["n1"].verdict, HostVerdict::Change);
        assert!(deliberate.reinstall);
        let install = action(&deliberate, "n1", ActionKind::Install);
        assert!(!install.is_blocked());
        // This one DOES interrupt something: the machine answers and runs a
        // system, so the plan asks for that as well as for the disk.
        assert_eq!(install.disruption, Disruption::Reboot);
        let classes: Vec<ApprovalClass> = deliberate.approvals.iter().map(|a| a.class).collect();
        assert!(classes.contains(&ApprovalClass::Destructive), "{classes:?}");
        assert!(classes.contains(&ApprovalClass::Disruptive), "{classes:?}");
        let said = deliberate.hosts["n1"].reasons.join(" ");
        assert!(
            said.is_empty(),
            "a host that is not blocked has no reasons: {said}"
        );

        // …and it is a DIFFERENT plan, which is what makes the approval
        // impossible to carry over.
        assert_ne!(plan.plan_id, deliberate.plan_id);
    }

    #[test]
    fn a_host_with_no_install_table_says_what_is_missing() {
        let mut fleet = onebox_enrolled();
        fleet.hosts.get_mut("n1").expect("n1").install = None;
        fleet.manifest_id =
            crate::ids::content_id(crate::ids::IdKind::Manifest, &fleet).expect("hashes");
        let release = release_of(fleet);
        let mut observation = observed(&release, at(TAKEN));
        observation.hosts.get_mut("n1").expect("n1").reachable = false;

        let plan = install_plan(&release, "host=n1", &observation, false);
        assert_eq!(plan.hosts["n1"].verdict, HostVerdict::Blocked);
        let why = plan.hosts["n1"].reasons.join(" ");
        assert!(why.contains("no `install` table"), "{why}");
        assert!(why.contains("plan --kind upgrade"), "{why}");
        // And there is no install step at all: there is no disk to name.
        assert_eq!(
            kinds(&plan, "n1"),
            [ActionKind::Preflight, ActionKind::Verify]
        );
    }

    #[test]
    fn an_install_plan_stages_nothing_and_locks_nothing() {
        // The closure travels in the medium and the machine is not running,
        // so every step an upgrade needs would be a step against a host
        // that is not there.
        let (release, observation) = nothing_installed_yet();
        let plan = install_plan(&release, "all", &observation, false);
        for host in ["box", "n1", "n2"] {
            let steps = kinds(&plan, host);
            for unwanted in [
                ActionKind::Stage,
                ActionKind::Lock,
                ActionKind::Activate,
                ActionKind::Confirm,
                ActionKind::Reboot,
                ActionKind::Unlock,
            ] {
                assert!(
                    !steps.contains(&unwanted),
                    "{host} has a {unwanted}: {steps:?}"
                );
            }
        }
    }

    #[test]
    fn the_reinstall_flag_is_only_ever_true_for_an_install() {
        let (release, observation) = upgrade(&["n1"], false);
        let plan = plan(
            &release,
            "all",
            &observation,
            None,
            &plan_policy(PlanKind::Upgrade).with_reinstall(true),
            at(NOW),
        )
        .expect("plans");
        assert!(
            !plan.reinstall,
            "an upgrade can never carry a word that means `destroy this disk`"
        );
    }

    #[test]
    fn a_host_that_is_deployed_as_context_is_never_installed() {
        let (release, observation) = nothing_installed_yet();
        let mut fleet = release.resolved_fleet.clone();
        fleet.hosts.get_mut("n1").expect("n1").deployment = crate::manifest::Deployment::Context;
        fleet.manifest_id =
            crate::ids::content_id(crate::ids::IdKind::Manifest, &fleet).expect("hashes");
        let release = release_of(fleet);
        let plan = install_plan(&release, "host=n1", &observation, false);
        let why = plan.hosts["n1"].reasons.join(" ");
        assert!(why.contains("never installs one"), "{why}");
    }

    #[test]
    fn a_host_that_already_runs_it_gets_two_steps_and_neither_touches_anything() {
        // V10.
        let (release, observation) = upgrade(&["n1"], false);
        let plan = planned(&release, "all", &observation);

        assert_eq!(plan.hosts["box"].verdict, HostVerdict::Unchanged);
        assert_eq!(
            kinds(&plan, "box"),
            [ActionKind::Preflight, ActionKind::Verify]
        );
        for a in plan.actions_for("box") {
            assert_eq!(a.disruption, Disruption::None, "{:?}", a.kind);
            assert_eq!(a.approval_class, ApprovalClass::None);
            assert!(!a.is_blocked());
        }
        assert!(!plan.hosts["box"].reboot_required);
        // and nothing is staged, activated or delivered for it
        assert!(!kinds(&plan, "box").contains(&ActionKind::Stage));
        assert!(!kinds(&plan, "box").contains(&ActionKind::DeliverSecret));
    }

    #[test]
    fn a_changed_host_gets_the_whole_sequence_in_order() {
        let (release, observation) = upgrade(&["n1"], false);
        let plan = planned(&release, "host=n1", &observation);
        assert_eq!(plan.hosts["n1"].verdict, HostVerdict::Change);
        assert_eq!(
            kinds(&plan, "n1"),
            [
                ActionKind::Preflight,
                ActionKind::Lock,
                ActionKind::Stage,
                ActionKind::Cordon,
                ActionKind::Drain,
                ActionKind::Activate,
                ActionKind::Verify,
                ActionKind::Confirm,
                ActionKind::Uncordon,
                ActionKind::Unlock,
            ]
        );
        let activate = action(&plan, "n1", ActionKind::Activate);
        assert_eq!(
            activate.current.as_deref(),
            Some(observation.hosts["n1"].current_system.as_deref().unwrap())
        );
        assert_eq!(
            activate.desired.as_deref(),
            Some(release.artifacts["n1"].toplevel.store_path.as_str())
        );
        assert_eq!(activate.rollback.mode, RollbackMode::Switch);
        assert_eq!(
            activate.rollback.confirm_within_secs,
            CONFIRM_WITHIN_SWITCH_SECS
        );
        assert!(!activate.reboot_required);
        assert_eq!(activate.approval_class, ApprovalClass::Disruptive);
        assert_eq!(activate.parallel_group, "n1");
    }

    #[test]
    fn only_the_hosts_whose_system_changed_are_changed() {
        // V11: one profile changes, and exactly its hosts move.
        let (release, observation) = upgrade(&["n1", "n2"], false);
        let plan = planned(&release, "all", &observation);
        assert_eq!(plan.hosts["box"].verdict, HostVerdict::Unchanged);
        assert_eq!(plan.hosts["n1"].verdict, HostVerdict::Change);
        assert_eq!(plan.hosts["n2"].verdict, HostVerdict::Change);
        assert_eq!(
            plan.actions
                .iter()
                .filter(|a| a.kind == ActionKind::Activate)
                .map(|a| a.host.as_str())
                .collect::<Vec<_>>(),
            ["n1", "n2"]
        );
    }

    #[test]
    fn a_changed_kernel_is_a_reboot_class_and_never_a_quiet_one() {
        // V15.
        let (release, observation) = upgrade(&["n1"], true);
        let plan = planned(&release, "host=n1", &observation);
        assert!(plan.hosts["n1"].reboot_required);
        let activate = action(&plan, "n1", ActionKind::Activate);
        assert!(activate.reboot_required);
        assert_eq!(activate.rollback.mode, RollbackMode::Boot);
        assert_eq!(
            activate.rollback.confirm_within_secs,
            CONFIRM_WITHIN_BOOT_SECS
        );
        // `reboot = approve` in the fixture, so somebody has to say yes
        assert_eq!(activate.approval_class, ApprovalClass::Reboot);
        assert!(
            plan.approvals
                .iter()
                .any(|a| a.class == ApprovalClass::Reboot),
            "{:?}",
            plan.approvals
        );
        let reboot = action(&plan, "n1", ActionKind::Reboot);
        assert_eq!(reboot.disruption, Disruption::Reboot);
        assert!(
            activate
                .preconditions
                .iter()
                .any(|p| p.contains("--mode boot")),
            "{:?}",
            activate.preconditions
        );
        // and the preflight carries the fact it was decided from
        assert!(
            action(&plan, "n1", ActionKind::Preflight)
                .preconditions
                .iter()
                .any(|p| p.contains("the kernel") && p.contains("next boot")),
            "{:?}",
            action(&plan, "n1", ActionKind::Preflight).preconditions
        );
    }

    #[test]
    fn a_kernel_change_under_reboot_never_is_blocked_rather_than_taken() {
        let base = onebox_enrolled();
        let running = release_of(base.clone());
        let observation = observed(&running, at(TAKEN));
        let mut fleet = base;
        fleet.hosts.get_mut("n1").unwrap().rollout.reboot = crate::manifest::RebootPolicy::Never;
        let release = with_new_systems(fleet, &["n1"], true);
        let plan = planned(&release, "host=n1", &observation);

        assert_eq!(plan.hosts["n1"].verdict, HostVerdict::Blocked);
        let activate = action(&plan, "n1", ActionKind::Activate);
        let why = activate.blocked.as_deref().unwrap_or_default();
        assert!(why.contains("reboot = never"), "{why}");
        // and the step that only looks is still allowed to look
        assert!(!action(&plan, "n1", ActionKind::Preflight).is_blocked());
        // nothing that would interrupt it is left runnable
        for a in plan.actions_for("n1") {
            if a.disruption != Disruption::None {
                assert!(a.is_blocked(), "{:?} should be blocked", a.kind);
            }
        }
        assert!(
            plan.approvals.is_empty(),
            "a blocked step needs no approval"
        );
    }

    #[test]
    fn a_kernel_nobody_could_read_is_a_reboot_class_and_an_unknown() {
        let (release, observation) = upgrade(&["n1"], false);
        let mut observation = observation;
        observation.hosts.get_mut("n1").unwrap().kernel_booted = None;
        let plan = planned(&release, "host=n1", &observation);
        assert!(plan.hosts["n1"].reboot_required);
        assert!(
            plan.unknowns
                .iter()
                .any(|u| u.host.as_deref() == Some("n1") && u.reason.contains("assumes a reboot")),
            "{:?}",
            plan.unknowns
        );
    }

    #[test]
    fn switched_and_never_booted_is_a_reboot_and_nothing_else() {
        let (release, observation) = upgrade(&["n1"], false);
        let desired = release.artifacts["n1"].toplevel.store_path.clone();
        let mut observation = observation;
        let n1 = observation.hosts.get_mut("n1").unwrap();
        let previous = n1.booted_system.clone();
        n1.current_system = Some(desired.clone());
        n1.next_boot_system = Some(desired.clone());
        // booted_system stays what it was: switched, never booted.
        let plan = planned(&release, "host=n1", &observation);

        assert_eq!(plan.hosts["n1"].verdict, HostVerdict::Change);
        let steps = kinds(&plan, "n1");
        assert!(!steps.contains(&ActionKind::Stage), "{steps:?}");
        assert!(!steps.contains(&ActionKind::Activate), "{steps:?}");
        assert!(!steps.contains(&ActionKind::Confirm), "{steps:?}");
        assert!(steps.contains(&ActionKind::Reboot), "{steps:?}");
        let reboot = action(&plan, "n1", ActionKind::Reboot);
        assert_eq!(reboot.current, previous);
        assert_eq!(reboot.desired.as_deref(), Some(desired.as_str()));
    }

    #[test]
    fn a_bootstrap_does_not_cordon_a_node_the_cluster_has_never_seen() {
        // The first `apply` of an agent's life: it has a host key, it has no
        // certificate, and the cluster it will report to does not know it
        // exists. `meister node cordon n1 --cluster …` would be a command
        // about a node nobody ever registered.
        let base = onebox_enrolled();
        let running = release_of(base.clone());
        let mut observation = observed(&running, at(TAKEN));
        for host in observation.hosts.values_mut() {
            host.enrolled = false;
            host.credentials.values_mut().for_each(|v| *v = None);
            host.units
                .values_mut()
                .for_each(|v| *v = "inactive".to_string());
        }
        let release = with_new_systems(base, &["box", "n1", "n2"], false);
        let policy = plan_policy_with_certificates(PlanKind::Bootstrap, &release.resolved_fleet);
        let plan = plan(&release, "all", &observation, None, &policy, at(NOW)).unwrap();

        for id in ["box", "n1", "n2"] {
            let steps = kinds(&plan, id);
            assert!(!steps.contains(&ActionKind::Cordon), "{id}: {steps:?}");
            assert!(!steps.contains(&ActionKind::Drain), "{id}: {steps:?}");
            assert!(!steps.contains(&ActionKind::Uncordon), "{id}: {steps:?}");
            assert!(steps.contains(&ActionKind::Activate), "{id}: {steps:?}");
        }

        // …and the same fleet once it HAS its identities is drained like any
        // other: what changed is the state of the host, not the kind of plan.
        let enrolled = observed(&release_of(onebox_enrolled()), at(TAKEN));
        let with_identities =
            crate::plan::plan(&release, "all", &enrolled, None, &policy, at(NOW)).unwrap();
        let steps = kinds(&with_identities, "n1");
        assert!(steps.contains(&ActionKind::Cordon), "{steps:?}");
        assert!(steps.contains(&ActionKind::Drain), "{steps:?}");
    }

    // --- lane 3-integration: the boot nobody inside the machine owns ---

    /// The same fleet with `n1` turned into a guest whose hypervisor loads
    /// its kernel, and a release that moves it.
    fn upgrade_direct(new_kernel: bool) -> (ReleaseManifest, Observations) {
        let base = crate::fixtures::with_direct_host(onebox_enrolled(), "n1");
        let running = crate::fixtures::direct_release_of(base.clone());
        let observation = observed(&running, at(TAKEN));
        let release = crate::fixtures::direct_release_of(crate::fixtures::with_new_toplevels(
            base,
            &["n1"],
            new_kernel,
        ));
        (release, observation)
    }

    // --- lane 5C ---

    fn upgrade_grub(new_kernel: bool) -> (ReleaseManifest, Observations) {
        let base = crate::fixtures::with_grub_host(onebox_enrolled(), "n1");
        let running = release_of(base.clone());
        let observation = observed(&running, at(TAKEN));
        let release = release_of(crate::fixtures::with_new_toplevels(
            base,
            &["n1"],
            new_kernel,
        ));
        (release, observation)
    }

    #[test]
    fn a_kernel_change_on_a_grub_host_is_switched_and_rebooted_by_the_machine_itself() {
        // L2 finding N4. Every guest built from
        // `packages.managed-disk-image` is a legacy-MBR grub machine. The
        // inventory had no word for one, so the lab called it `uefi`,
        // `apply` passed `--mode boot`, and the helper refused: "there is
        // no boot fallback on this host: bootctl says systemd-boot is not
        // installed". Such a host was not deployable at all as soon as a
        // release touched its kernel.
        let (release, observation) = upgrade_grub(true);
        let plan = planned(&release, "host=n1", &observation);

        assert!(plan.hosts["n1"].reboot_required);
        let steps = kinds(&plan, "n1");
        // It reboots ITSELF: the loader is on its own disk, so this is an
        // ordinary reboot and never the provider's.
        assert!(steps.contains(&ActionKind::Reboot), "{steps:?}");
        assert!(!steps.contains(&ActionKind::ProviderReboot), "{steps:?}");

        // And the one thing that makes `grub` a value of its own: the
        // activation in front of that reboot is a switch, because
        // `bootctl set-oneshot` is what a boot rollback is made of.
        let activate = action(&plan, "n1", ActionKind::Activate);
        assert_eq!(activate.rollback.mode, RollbackMode::Switch);
        assert_eq!(
            activate.rollback.confirm_within_secs,
            CONFIRM_WITHIN_SWITCH_SECS
        );
        assert!(
            activate.preconditions.iter().any(|p| p.contains("grub"))
                || activate
                    .preconditions
                    .iter()
                    .any(|p| p.contains("--mode switch")),
            "the plan says why, in a sentence an operator reads: {:?}",
            activate.preconditions
        );
    }

    #[test]
    fn a_grub_host_that_changes_only_its_userland_is_an_ordinary_switch() {
        // The other half: nothing about `grub` makes an ordinary release
        // special. There is no reboot, and the way back is the same one
        // every switch has.
        let (release, observation) = upgrade_grub(false);
        let plan = planned(&release, "host=n1", &observation);
        assert!(!plan.hosts["n1"].reboot_required);
        let steps = kinds(&plan, "n1");
        assert!(!steps.contains(&ActionKind::Reboot), "{steps:?}");
        assert_eq!(
            action(&plan, "n1", ActionKind::Activate).rollback.mode,
            RollbackMode::Switch
        );
    }

    // --- end lane 5C ---

    #[test]
    fn a_kernel_change_on_a_direct_host_is_a_provider_reboot_with_the_bundle() {
        let (release, observation) = upgrade_direct(true);
        let plan = planned(&release, "host=n1", &observation);

        assert!(plan.hosts["n1"].reboot_required);
        let steps = kinds(&plan, "n1");
        assert!(
            steps.contains(&ActionKind::ProviderReboot),
            "a host whose kernel comes from outside is rebooted from outside: {steps:?}"
        );
        assert!(
            !steps.contains(&ActionKind::Reboot),
            "`systemctl reboot` would come back on the bytes the provider loaded last: {steps:?}"
        );

        // The way back of the activation is the userland one, because the
        // other one is a boot menu this machine has not got.
        let activate = action(&plan, "n1", ActionKind::Activate);
        assert_eq!(activate.rollback.mode, RollbackMode::Switch);
        assert_eq!(
            activate.rollback.confirm_within_secs,
            CONFIRM_WITHIN_SWITCH_SECS
        );

        // …and the confirmation comes BEFORE the halt, or the machine would
        // take itself back while somebody arranges a hypervisor.
        let order: Vec<ActionKind> = steps.clone();
        let at_of = |kind: ActionKind| {
            order
                .iter()
                .position(|k| *k == kind)
                .unwrap_or_else(|| panic!("{kind} is not in {order:?}"))
        };
        assert!(at_of(ActionKind::Activate) < at_of(ActionKind::Verify));
        assert!(at_of(ActionKind::Verify) < at_of(ActionKind::Confirm));
        assert!(at_of(ActionKind::Confirm) < at_of(ActionKind::ProviderReboot));
        assert_eq!(
            order.iter().filter(|k| **k == ActionKind::Verify).count(),
            2,
            "one verify for the switch and one for what the provider booted: {order:?}"
        );

        let halt = action(&plan, "n1", ActionKind::ProviderReboot);
        assert_eq!(halt.disruption, Disruption::Reboot);
        assert!(halt.reboot_required);
        // `reboot = approve` in the fixture, so somebody says yes to this.
        assert_eq!(halt.approval_class, ApprovalClass::Reboot);
        assert!(
            plan.approvals
                .iter()
                .any(|a| a.class == ApprovalClass::Reboot),
            "{:?}",
            plan.approvals
        );

        // The payload: the bytes a provider is handed, in the plan itself.
        let bundle = halt
            .provider_boot
            .as_ref()
            .expect("the step carries the bundle it is about");
        let from_release = release.artifacts["n1"]
            .direct_boot
            .as_ref()
            .expect("a direct host has a bundle");
        assert_eq!(bundle, from_release);
        assert!(
            bundle
                .cmdline
                .contains(&release.artifacts["n1"].toplevel.store_path),
            "the command line names the system the kernel is to start: {}",
            bundle.cmdline
        );
        // And nothing else carries one.
        for step in plan.actions_for("n1") {
            if step.kind != ActionKind::ProviderReboot {
                assert!(step.provider_boot.is_none(), "{:?}", step.kind);
            }
        }
        // The sentence the halt is read with.
        let said = halt.preconditions.join(" ");
        assert!(said.contains(&bundle.kernel.store_path), "{said}");
        assert!(said.contains(&bundle.initrd.store_path), "{said}");
        assert!(said.contains("the kernel it booted before"), "{said}");
    }

    #[test]
    fn the_same_kernel_change_on_a_uefi_host_is_an_ordinary_reboot() {
        // The counter-probe of the test above, on the same fixture with the
        // one field that differs.
        let (release, observation) = upgrade(&["n1"], true);
        let plan = planned(&release, "host=n1", &observation);
        let steps = kinds(&plan, "n1");
        assert!(steps.contains(&ActionKind::Reboot), "{steps:?}");
        assert!(!steps.contains(&ActionKind::ProviderReboot), "{steps:?}");
        assert_eq!(
            action(&plan, "n1", ActionKind::Activate).rollback.mode,
            RollbackMode::Boot
        );
        assert_eq!(
            steps.iter().filter(|k| **k == ActionKind::Verify).count(),
            1,
            "{steps:?}"
        );
    }

    #[test]
    fn a_userland_change_on_a_direct_host_reboots_nothing() {
        // The kernel, the initrd and the command line are the same three
        // fields for both boot modes: a release that changes none of them
        // needs no provider and no reboot.
        let (release, observation) = upgrade_direct(false);
        let plan = planned(&release, "host=n1", &observation);
        let steps = kinds(&plan, "n1");
        assert!(!plan.hosts["n1"].reboot_required, "{steps:?}");
        assert!(!steps.contains(&ActionKind::ProviderReboot), "{steps:?}");
        assert!(!steps.contains(&ActionKind::Reboot), "{steps:?}");
        assert_eq!(
            steps.iter().filter(|k| **k == ActionKind::Verify).count(),
            1,
            "{steps:?}"
        );
    }

    #[test]
    fn switched_and_never_booted_on_a_direct_host_waits_for_its_provider() {
        // The shape a halt leaves behind when somebody re-plans instead of
        // resuming: the host runs the release and booted the one before it.
        // `systemctl reboot` here would bring it back on the old kernel and
        // the run would wait ten minutes for a boot that already happened.
        let (release, observation) = upgrade_direct(true);
        let desired = release.artifacts["n1"].toplevel.store_path.clone();
        let mut observation = observation;
        let n1 = observation.hosts.get_mut("n1").unwrap();
        n1.current_system = Some(desired.clone());
        n1.next_boot_system = Some(desired.clone());
        let plan = planned(&release, "host=n1", &observation);

        let steps = kinds(&plan, "n1");
        assert!(!steps.contains(&ActionKind::Stage), "{steps:?}");
        assert!(!steps.contains(&ActionKind::Activate), "{steps:?}");
        assert!(!steps.contains(&ActionKind::Reboot), "{steps:?}");
        assert!(steps.contains(&ActionKind::ProviderReboot), "{steps:?}");
        let halt = action(&plan, "n1", ActionKind::ProviderReboot);
        assert!(halt.provider_boot.is_some());
        assert_eq!(halt.desired.as_deref(), Some(desired.as_str()));
    }

    #[test]
    fn a_direct_host_under_reboot_never_is_blocked_like_any_other() {
        let base = crate::fixtures::with_direct_host(onebox_enrolled(), "n1");
        let running = crate::fixtures::direct_release_of(base.clone());
        let observation = observed(&running, at(TAKEN));
        let mut fleet = base;
        fleet.hosts.get_mut("n1").unwrap().rollout.reboot = crate::manifest::RebootPolicy::Never;
        let release = crate::fixtures::direct_release_of(crate::fixtures::with_new_toplevels(
            fleet,
            &["n1"],
            true,
        ));
        let plan = planned(&release, "host=n1", &observation);

        assert_eq!(plan.hosts["n1"].verdict, HostVerdict::Blocked);
        let halt = action(&plan, "n1", ActionKind::ProviderReboot);
        let why = halt.blocked.as_deref().unwrap_or_default();
        assert!(why.contains("reboot = never"), "{why}");
        assert!(plan.approvals.is_empty(), "{:?}", plan.approvals);
    }

    #[test]
    fn a_release_without_the_bundle_of_a_direct_host_is_refused_by_name() {
        // `release::bind` will not make one (3A holds both directions), so
        // this is the second door: a plan is what an adapter acts on, and a
        // halt whose payload is missing is a halt nobody can carry out.
        let (release, observation) = upgrade_direct(true);
        let mut release = release;
        release.artifacts.get_mut("n1").unwrap().direct_boot = None;
        let plan = planned(&release, "host=n1", &observation);

        assert_eq!(plan.hosts["n1"].verdict, HostVerdict::Blocked);
        let why = plan.hosts["n1"].reasons.join(" ");
        assert!(why.contains("no direct-boot bundle for n1"), "{why}");
    }

    #[test]
    fn a_required_booted_check_on_a_direct_host_is_said_before_it_rolls_back() {
        // Between the switch and the provider's reboot such a host runs the
        // release and has booted the one before it. A required `booted`
        // therefore fails the verify in front of the confirmation, and the
        // switch would be taken back once per kernel — so the plan says so
        // instead of doing it.
        let base = crate::fixtures::with_direct_host(onebox_enrolled(), "n1");
        let running = crate::fixtures::direct_release_of(base.clone());
        let observation = observed(&running, at(TAKEN));
        let mut fleet = base;
        fleet
            .hosts
            .get_mut("n1")
            .unwrap()
            .checks
            .required
            .push("booted".to_string());
        let release = crate::fixtures::direct_release_of(crate::fixtures::with_new_toplevels(
            fleet,
            &["n1"],
            true,
        ));
        let plan = planned(&release, "host=n1", &observation);

        assert_eq!(plan.hosts["n1"].verdict, HostVerdict::Blocked);
        let why = plan.hosts["n1"].reasons.join(" ");
        assert!(why.contains("requires the check `booted`"), "{why}");
        // …and a uefi host with the same required check is untouched by it.
        let (release, observation) = upgrade(&["n2"], true);
        let plan = planned(&release, "host=n2", &observation);
        assert_eq!(plan.hosts["n2"].verdict, HostVerdict::Change);
    }

    #[test]
    fn a_plan_with_a_provider_reboot_round_trips_through_its_own_json() {
        let (release, observation) = upgrade_direct(true);
        let plan = planned(&release, "host=n1", &observation);
        let text = String::from_utf8(plan.to_json().unwrap()).unwrap();
        let back = DeploymentPlan::from_json(&text, "the round trip").expect("it parses back");
        assert_eq!(back, plan);
        assert!(back.id_matches().unwrap());
        // The one step that carries a payload is the one that spells it out
        // in the file, and no other step gains a null field.
        assert!(text.contains("\"provider-reboot\""), "{text}");
        assert_eq!(
            text.matches("\"provider_boot\"").count(),
            1,
            "only the halt carries one"
        );
    }

    #[test]
    fn a_plan_of_a_fleet_that_boots_itself_hashes_to_what_it_always_did() {
        // The new field is absent rather than null on every other plan, so
        // adding it did not rename every id in every operator's repository.
        let (release, observation) = upgrade(&["n1"], true);
        let plan = planned(&release, "host=n1", &observation);
        let text = String::from_utf8(plan.to_json().unwrap()).unwrap();
        assert!(!text.contains("provider_boot"), "{text}");
    }

    #[test]
    fn wanted_next_boot_and_running_are_three_facts() {
        // The same host, the same desired system, three different answers.
        let (release, observation) = upgrade(&["n1"], false);
        let desired = release.artifacts["n1"].toplevel.store_path.clone();

        let mut all_three = observation.clone();
        let n1 = all_three.hosts.get_mut("n1").unwrap();
        n1.current_system = Some(desired.clone());
        n1.next_boot_system = Some(desired.clone());
        n1.booted_system = Some(desired.clone());
        n1.kernel_booted = Some(BootedKernel {
            kernel_store_path: release.artifacts["n1"].boot.kernel_store_path.clone(),
            initrd_store_path: release.artifacts["n1"].boot.initrd_store_path.clone(),
            kernel_params_sha256: release.artifacts["n1"].boot.kernel_params_sha256.clone(),
        });
        assert_eq!(
            planned(&release, "host=n1", &all_three).hosts["n1"].verdict,
            HostVerdict::Unchanged
        );

        // Switched but the boot loader still points elsewhere: not a no-op.
        let mut next_is_old = all_three.clone();
        next_is_old.hosts.get_mut("n1").unwrap().next_boot_system =
            Some("/nix/store/somewhere-else".to_string());
        assert_eq!(
            planned(&release, "host=n1", &next_is_old).hosts["n1"].verdict,
            HostVerdict::Change
        );
    }

    #[test]
    fn a_host_key_that_is_not_the_enrolled_one_blocks_the_host() {
        let (release, observation) = upgrade(&["n1"], false);
        let mut observation = observation;
        observation
            .hosts
            .get_mut("n1")
            .unwrap()
            .identity
            .host_key_fingerprint = Some("SHA256:somebody-else".to_string());
        let plan = planned(&release, "host=n1", &observation);

        assert_eq!(plan.hosts["n1"].verdict, HostVerdict::Blocked);
        assert!(
            plan.hosts["n1"].reasons[0].contains("identity changed"),
            "{:?}",
            plan.hosts["n1"].reasons
        );
        // Everything but the two that only look is stopped — a changed
        // identity is not a quorum problem, it is a different machine.
        for a in plan.actions_for("n1") {
            match a.kind {
                ActionKind::Preflight | ActionKind::Verify => assert!(!a.is_blocked()),
                _ => assert!(a.is_blocked(), "{:?} should be blocked", a.kind),
            }
        }
    }

    #[test]
    fn a_host_the_fleet_has_no_key_for_is_blocked_in_every_kind_of_plan() {
        // n2 has no host key in the fixture — that is exactly this state.
        // Nothing can connect to it, so nothing can be planned for it: a
        // bootstrap delivers certificates and does not enroll an ssh key.
        let base = onebox();
        let running = release_of(base.clone());
        let observation = observed(&running, at(TAKEN));
        let release = with_new_systems(base, &["n2"], false);
        for kind in [PlanKind::Upgrade, PlanKind::Bootstrap] {
            let made = plan(
                &release,
                "host=n2",
                &observation,
                None,
                &plan_policy(kind),
                at(NOW),
            )
            .unwrap();
            assert_eq!(made.hosts["n2"].verdict, HostVerdict::Unenrolled, "{kind}");
            let why = &made.hosts["n2"].reasons[0];
            assert!(why.contains("no host key for n2"), "{kind}: {why}");
            assert!(
                why.contains("keys enroll n2 --fingerprint"),
                "{kind}: {why}"
            );
            assert!(
                action(&made, "n2", ActionKind::Activate).is_blocked(),
                "{kind}"
            );
        }
    }

    #[test]
    fn a_host_with_a_key_and_no_certificate_is_what_a_bootstrap_is_for() {
        // The other half of the same distinction: the ssh key is enrolled,
        // the service identity is not. An upgrade cannot act; a bootstrap
        // is exactly the plan that delivers it.
        let base = onebox_enrolled();
        let running = release_of(base.clone());
        let mut observation = observed(&running, at(TAKEN));
        let n2 = observation.hosts.get_mut("n2").unwrap();
        n2.enrolled = false;
        // And a host that has no identity has not been given the fleet's CA
        // certificate either: that is the file it would check one against,
        // and it is what this bootstrap has to deliver (lane 3B).
        n2.credentials.insert("ca-bundle".to_string(), None);
        let release = with_new_systems(base, &["n2"], false);

        let upgraded = planned(&release, "host=n2", &observation);
        assert_eq!(upgraded.hosts["n2"].verdict, HostVerdict::Unenrolled);
        let why = &upgraded.hosts["n2"].reasons[0];
        assert!(why.contains("reports no identity of its own"), "{why}");
        assert!(why.contains("--kind bootstrap"), "{why}");

        let bootstrapped = plan(
            &release,
            "host=n2",
            &observation,
            None,
            &plan_policy_with_certificates(PlanKind::Bootstrap, &release.resolved_fleet),
            at(NOW),
        )
        .unwrap();
        assert_eq!(
            bootstrapped.hosts["n2"].verdict,
            HostVerdict::Change,
            "{:?}",
            bootstrapped.hosts["n2"].reasons
        );
        assert!(
            kinds(&bootstrapped, "n2").contains(&ActionKind::DeliverSecret),
            "{:?}",
            kinds(&bootstrapped, "n2")
        );
    }

    #[test]
    fn an_open_transaction_sends_the_operator_to_resume_and_not_to_a_second_run() {
        let (release, observation) = upgrade(&["n1"], false);
        let mut observation = observation;
        observation.hosts.get_mut("n1").unwrap().open_txns = vec![Txn {
            id: "txn-7".to_string(),
            state: TxnState::Pending,
            target_system: Some("/nix/store/whatever".to_string()),
            deadline: Some(at("2026-09-21T11:00:00Z")),
            run_id: Some("0192-run".to_string()),
        }];
        let plan = planned(&release, "host=n1", &observation);
        let why = &plan.hosts["n1"].reasons[0];
        assert!(why.contains("txn-7"), "{why}");
        assert!(why.contains("--resume"), "{why}");
        assert_eq!(plan.hosts["n1"].verdict, HostVerdict::Blocked);
    }

    #[test]
    fn a_lock_somebody_else_holds_blocks_and_names_them() {
        let (release, observation) = upgrade(&["n1"], false);
        let mut observation = observation;
        observation.hosts.get_mut("n1").unwrap().lock = Some(Lock {
            run_id: "0192-other".to_string(),
            operator: "silas@manacor".to_string(),
            pid: 4711,
            acquired_at: at("2026-09-21T11:30:00Z"),
        });
        let plan = planned(&release, "host=n1", &observation);
        let why = &plan.hosts["n1"].reasons[0];
        assert!(why.contains("0192-other"), "{why}");
        assert!(why.contains("silas@manacor"), "{why}");
        assert!(why.contains("--takeover"), "{why}");
    }

    #[test]
    fn a_required_mount_that_is_missing_blocks_and_says_there_is_no_fallback() {
        // V19.
        let (release, observation) = upgrade(&["n1"], false);
        let mut observation = observation;
        observation.hosts.get_mut("n1").unwrap().mounts.clear();
        let plan = planned(&release, "host=n1", &observation);
        let why = &plan.hosts["n1"].reasons[0];
        assert!(why.contains("/var/lib/meister-data"), "{why}");
        assert!(why.contains("no fallback to the root disk"), "{why}");
    }

    #[test]
    fn a_declared_capability_that_is_not_there_blocks() {
        let (release, observation) = upgrade(&["n1"], false);
        let mut observation = observation;
        observation
            .hosts
            .get_mut("n1")
            .unwrap()
            .capabilities
            .clear();
        let plan = planned(&release, "host=n1", &observation);
        assert!(
            plan.hosts["n1"].reasons.iter().any(|r| r.contains("kvm")),
            "{:?}",
            plan.hosts["n1"].reasons
        );
    }

    // --- lane 4A: the hardware preflight ------------------------------------

    /// The one sentence a blocked host gives, joined, so that a test can
    /// look for a number in it.
    fn why(plan: &DeploymentPlan, id: &str) -> String {
        plan.hosts[id].reasons.join(" ")
    }

    #[test]
    fn a_closure_that_does_not_fit_blocks_with_both_numbers() {
        let (release, observation) = upgrade(&["n1"], false);
        let closure = release.artifacts["n1"].toplevel.closure_size;
        let mut observation = observation;
        observation.hosts.get_mut("n1").unwrap().disk_free_nix_bytes = Some(closure - 1);
        let plan = planned(&release, "host=n1", &observation);
        assert_eq!(plan.hosts["n1"].verdict, HostVerdict::Blocked);
        let why = why(&plan, "n1");
        // Both numbers, because "not enough room" without them is a
        // sentence nobody can act on.
        assert!(why.contains(&(closure - 1).to_string()), "{why}");
        assert!(why.contains(&closure.to_string()), "{why}");
        // And the preflight itself is never blocked: it is the step whose
        // job is to report exactly this.
        assert!(!action(&plan, "n1", ActionKind::Preflight).is_blocked());
        assert!(action(&plan, "n1", ActionKind::Stage).is_blocked());
    }

    #[test]
    fn room_that_is_exactly_enough_is_enough() {
        // The boundary, because `<` and `<=` is the whole difference
        // between a fleet that rolls and a fleet that does not.
        let (release, observation) = upgrade(&["n1"], false);
        let closure = release.artifacts["n1"].toplevel.closure_size;
        let mut observation = observation;
        observation.hosts.get_mut("n1").unwrap().disk_free_nix_bytes = Some(closure);
        let plan = planned(&release, "host=n1", &observation);
        assert_eq!(plan.hosts["n1"].verdict, HostVerdict::Change);
    }

    #[test]
    fn a_host_that_needs_no_closure_is_not_blocked_by_a_disk_nobody_writes_to() {
        // The room question is about a COPY. A host that already runs the
        // release has nothing copied onto it, so a full disk on it is a
        // thing for its operator and not a reason to refuse to look at it.
        let release = release_of(onebox_enrolled());
        let mut observation = observed(&release, at(TAKEN));
        observation.hosts.get_mut("n1").unwrap().disk_free_nix_bytes = Some(1);
        let plan = planned(&release, "host=n1", &observation);
        assert_eq!(plan.hosts["n1"].verdict, HostVerdict::Unchanged);
        // And it is not claimed either: nothing was measured against
        // nothing.
        let said = action(&plan, "n1", ActionKind::Preflight)
            .preconditions
            .join(" ");
        assert!(!said.contains("free for a closure of"), "{said}");
        // The rest of the machine is still checked, because a card that is
        // gone is worth saying about a host that needs nothing.
        assert!(said.contains("has /dev/kvm"), "{said}");
    }

    #[test]
    fn a_store_whose_room_nobody_could_read_is_an_unknown_and_not_a_full_disk() {
        let (release, observation) = upgrade(&["n1"], false);
        let mut observation = observation;
        observation.hosts.get_mut("n1").unwrap().disk_free_nix_bytes = None;
        let plan = planned(&release, "host=n1", &observation);
        assert_eq!(plan.hosts["n1"].verdict, HostVerdict::Change);
        assert!(
            plan.unknowns
                .iter()
                .any(|u| u.host.as_deref() == Some("n1") && u.reason.contains("how much room")),
            "{:?}",
            plan.unknowns
        );
    }

    #[test]
    fn an_agent_without_dev_kvm_blocks_even_when_the_fleet_declared_nothing() {
        // Not a capability the inventory claims: the agent refuses to start
        // without the device, so for that role it is a fact about the role.
        let (release, observation) = upgrade(&["n1"], false);
        let mut observation = observation;
        let obs = observation.hosts.get_mut("n1").unwrap();
        obs.capabilities.clear();
        let mut fleet = release.resolved_fleet.clone();
        fleet.hosts.get_mut("n1").unwrap().hardware.capabilities = Vec::new();
        let mut release = release;
        release.resolved_fleet = fleet;
        let plan = planned(&release, "host=n1", &observation);
        let why = why(&plan, "n1");
        assert!(why.contains("/dev/kvm"), "{why}");
        assert!(why.contains("agent role"), "{why}");
    }

    #[test]
    fn a_declared_gpu_that_is_not_in_the_machine_blocks_with_its_address() {
        let (release, observation) = upgrade(&["n1"], false);
        let mut release = release;
        release
            .resolved_fleet
            .hosts
            .get_mut("n1")
            .unwrap()
            .hardware
            .gpus = vec![crate::manifest::Gpu {
            model: "NVIDIA RTX PRO 6000".to_string(),
            pci: "0000:41:00.0".to_string(),
            selected_for: Some("vfio".to_string()),
        }];
        let mut observation = observation;
        observation.hosts.get_mut("n1").unwrap().pci = vec![crate::observation::PciDevice {
            address: "0000:00:01.0".to_string(),
            vendor_device: "8086:1237".to_string(),
        }];
        let plan = planned(&release, "host=n1", &observation);
        let why = why(&plan, "n1");
        assert!(why.contains("0000:41:00.0"), "{why}");
        assert!(why.contains("NVIDIA RTX PRO 6000"), "{why}");
        // And it says what the machine DOES have, so that an operator can
        // correct the inventory without walking to the rack.
        assert!(why.contains("0000:00:01.0 (8086:1237)"), "{why}");
    }

    #[test]
    fn a_machine_whose_cards_nobody_could_list_blocks_and_says_so() {
        // An empty list is "nobody looked", not "there is no card". The two
        // read the same to a bool and not to a person.
        let (release, observation) = upgrade(&["n1"], false);
        let mut release = release;
        release
            .resolved_fleet
            .hosts
            .get_mut("n1")
            .unwrap()
            .hardware
            .gpus = vec![crate::manifest::Gpu {
            model: "NVIDIA RTX PRO 6000".to_string(),
            pci: "0000:41:00.0".to_string(),
            selected_for: None,
        }];
        let mut observation = observation;
        observation.hosts.get_mut("n1").unwrap().pci.clear();
        let plan = planned(&release, "host=n1", &observation);
        let why = why(&plan, "n1");
        assert!(why.contains("no PCI list at all"), "{why}");
        assert!(why.contains("nobody looked"), "{why}");
    }

    #[test]
    fn a_declared_mac_that_no_interface_has_blocks_and_names_the_ones_that_answered() {
        let (release, observation) = upgrade(&["n1"], false);
        let mut observation = observation;
        observation.hosts.get_mut("n1").unwrap().nics =
            vec![crate::observation::NetworkInterface {
                name: "eth0".to_string(),
                mac: "52:54:00:aa:bb:cc".to_string(),
            }];
        let declared = release.resolved_fleet.hosts["n1"].hardware.nics[0]
            .mac
            .clone();
        let plan = planned(&release, "host=n1", &observation);
        let why = why(&plan, "n1");
        assert!(why.contains(&declared), "{why}");
        assert!(why.contains("eth0 (52:54:00:aa:bb:cc)"), "{why}");
    }

    #[test]
    fn a_nic_that_answers_under_a_different_name_is_the_same_nic() {
        // The MAC is what the fleet enrolled; the name is what the kernel
        // handed out this boot. A rename must not block a rollout.
        let (release, observation) = upgrade(&["n1"], false);
        let declared = release.resolved_fleet.hosts["n1"].hardware.nics[0].clone();
        let mut observation = observation;
        observation.hosts.get_mut("n1").unwrap().nics =
            vec![crate::observation::NetworkInterface {
                name: "enp3s0f0".to_string(),
                mac: declared.mac.to_uppercase(),
            }];
        let plan = planned(&release, "host=n1", &observation);
        assert_eq!(plan.hosts["n1"].verdict, HostVerdict::Change);
        assert!(
            action(&plan, "n1", ActionKind::Preflight)
                .preconditions
                .iter()
                .any(|p| p.contains(&declared.mac)),
            "{:?}",
            action(&plan, "n1", ActionKind::Preflight).preconditions
        );
    }

    #[test]
    fn a_member_that_could_not_be_asked_is_not_an_empty_membership() {
        // What `vm-kernel-change` found: a host came back from the reboot
        // this rollout asked for, sshd answered before etcd did, and its
        // member list was empty. An empty list is "nobody could ask" — a
        // live member always names at least itself — and reading it as a
        // membership change blocks the whole group for a machine that is
        // merely still starting.
        let release = release_of(onebox_enrolled());
        let mut observation = observed(&release, at(TAKEN));
        let etcd = observation.hosts.get_mut("box").unwrap().etcd.as_mut();
        let etcd = etcd.expect("box is a raft member");
        etcd.members.clear();
        etcd.healthy = false;
        etcd.member_id = None;
        let plan = planned(&release, "all", &observation);
        let group = &plan.groups["box"];
        // Down, yes — and a singleton has no budget to lose, so it is not
        // blocked by that. What it must NOT say is that the fleet changed.
        assert_eq!(group.unhealthy_now, 1, "{group:?}");
        assert!(
            group.blocked.is_none(),
            "a member that is starting is not a membership change: {:?}",
            group.blocked
        );
    }

    #[test]
    fn a_membership_that_really_moved_still_blocks() {
        // The other side of the same coin: a member that ANSWERED with a
        // list that is not the declared one is exactly what the check is
        // for, and it still fires.
        let release = release_of(onebox_enrolled());
        let mut observation = observed(&release, at(TAKEN));
        let etcd = observation
            .hosts
            .get_mut("box")
            .unwrap()
            .etcd
            .as_mut()
            .expect("box is a raft member");
        etcd.members.push(crate::observation::EtcdMember {
            id: "9".to_string(),
            name: "somebody-else".to_string(),
            peer_urls: vec!["https://10.0.0.99:2380".to_string()],
            healthy: true,
        });
        let plan = planned(&release, "all", &observation);
        let why = plan.groups["box"].blocked.clone().unwrap_or_default();
        assert!(why.contains("somebody-else"), "{why}");
        assert!(why.contains("membership"), "{why}");
    }

    // --- lane 4A: the units the operator owns -------------------------------

    #[test]
    fn the_units_this_stack_owns_are_the_ones_a_role_adds() {
        // The constant, held against a real manifest rather than against
        // this file: `box` carries four roles and `n1` one, so every unit
        // `box` has and `n1` has not is a unit some MeisterStack module
        // brought. If a module ever grows a unit and nobody adds it here,
        // this test names it.
        let fleet = crate::fixtures::onebox();
        let box_units: BTreeSet<&str> = fleet.hosts["box"]
            .units
            .iter()
            .map(String::as_str)
            .collect();
        let agent_units: BTreeSet<&str> =
            fleet.hosts["n1"].units.iter().map(String::as_str).collect();
        let added: Vec<&str> = box_units.difference(&agent_units).copied().collect();
        assert!(!added.is_empty(), "the fixture has two host shapes");
        for unit in &added {
            assert!(
                STACK_UNITS.contains(unit),
                "{unit} is what a MeisterStack role adds and STACK_UNITS does not name it"
            );
        }
        // And the one unit both shapes share from this stack is named too.
        assert!(STACK_UNITS.contains(&"meister-agent.service"));
    }

    #[test]
    fn a_unit_this_tool_does_not_know_is_an_unknown_once_per_host() {
        let (release, observation) = upgrade(&["n1"], false);
        let mut release = release;
        let host = release.resolved_fleet.hosts.get_mut("n1").unwrap();
        host.units.push("node-exporter.service".to_string());
        host.units.push("operator-backup.timer".to_string());
        host.units.sort();
        let plan = planned(&release, "host=n1", &observation);
        let ours: Vec<&Unknown> = plan
            .unknowns
            .iter()
            .filter(|u| u.reason.contains("operator-owned unit"))
            .collect();
        assert_eq!(ours.len(), 1, "one entry per host, not per unit: {ours:?}");
        assert_eq!(ours[0].host.as_deref(), Some("n1"));
        assert!(ours[0].reason.contains("node-exporter.service"), "{ours:?}");
        assert!(ours[0].reason.contains("operator-backup.timer"), "{ours:?}");
        assert!(ours[0].reason.contains("is not modelled"), "{ours:?}");
        // An unknown is not a refusal: the plan still rolls.
        assert_eq!(plan.hosts["n1"].verdict, HostVerdict::Change);
    }

    #[test]
    fn a_unit_the_host_already_runs_is_not_new_and_a_unit_of_ours_is_never_an_unknown() {
        let (release, observation) = upgrade(&["n1"], false);
        let mut release = release;
        let host = release.resolved_fleet.hosts.get_mut("n1").unwrap();
        // One the machine already has, one of ours that it has not.
        host.units.push("node-exporter.service".to_string());
        host.units.push("alloy.service".to_string());
        host.units.sort();
        let mut observation = observation;
        observation
            .hosts
            .get_mut("n1")
            .unwrap()
            .generation_units
            .push("node-exporter.service".to_string());
        let plan = planned(&release, "host=n1", &observation);
        assert!(
            !plan
                .unknowns
                .iter()
                .any(|u| u.reason.contains("operator-owned unit")),
            "{:?}",
            plan.unknowns
        );
    }

    #[test]
    fn a_generation_whose_units_nobody_could_list_is_one_unknown_and_not_seventy() {
        // 4C's warning made into a test: "everything that is not meister"
        // over an empty list would be one unknown per unit, every run.
        let (release, observation) = upgrade(&["n1"], false);
        let mut observation = observation;
        observation
            .hosts
            .get_mut("n1")
            .unwrap()
            .generation_units
            .clear();
        let plan = planned(&release, "host=n1", &observation);
        let ours: Vec<&Unknown> = plan
            .unknowns
            .iter()
            .filter(|u| u.reason.contains("units"))
            .collect();
        assert_eq!(ours.len(), 1, "{ours:?}");
        assert!(ours[0].reason.contains("nobody could list"), "{ours:?}");
    }

    #[test]
    fn a_multi_role_host_is_one_interruption_and_not_two() {
        // 2B has the rule; this is the evidence at the waves and at the
        // approvals, which is where an operator meets it. `box` carries
        // cloud, cluster, agent and addons on one machine.
        let (release, observation) = upgrade(&["box"], false);
        let plan = planned(&release, "all", &observation);
        let acting: Vec<&Action> = plan
            .actions
            .iter()
            .filter(|a| a.host == "box" && !a.is_blocked())
            .collect();
        // One activation, one lock, one drain, one confirm. Four roles do
        // not make four interruptions of one machine.
        for kind in [
            ActionKind::Activate,
            ActionKind::Lock,
            ActionKind::Drain,
            ActionKind::Confirm,
            ActionKind::Unlock,
        ] {
            assert_eq!(
                acting.iter().filter(|a| a.kind == kind).count(),
                1,
                "{kind} on a four-role host: {:?}",
                acting.iter().map(|a| a.kind).collect::<Vec<_>>()
            );
        }
        // It sits in ONE wave and in one parallel group, so no other host
        // of its raft group can move at the same time.
        let waves: BTreeSet<u32> = acting.iter().map(|a| a.wave).collect();
        assert_eq!(waves.len(), 1, "{waves:?}");
        let groups: BTreeSet<&str> = acting.iter().map(|a| a.parallel_group.as_str()).collect();
        assert_eq!(groups, BTreeSet::from(["box"]));
        // And the approvals it needs are the union of the classes of that
        // one interruption, not one set per role.
        assert!(
            plan.approvals
                .iter()
                .filter(|a| a.class == ApprovalClass::Singleton)
                .count()
                <= 1,
            "{:?}",
            plan.approvals
        );
    }

    #[test]
    fn what_the_preflight_found_is_part_of_the_plan_and_not_only_of_the_run() {
        // The lane brief's point: the verdict is a contract, so it is in
        // `preconditions[]` of the `preflight` step where a reader and a
        // reviewer both find it.
        let (release, observation) = upgrade(&["n1"], false);
        let plan = planned(&release, "host=n1", &observation);
        let said = action(&plan, "n1", ActionKind::Preflight)
            .preconditions
            .join(" ");
        assert!(said.contains("free for a closure of"), "{said}");
        assert!(said.contains("has /dev/kvm"), "{said}");
        assert!(said.contains("answered"), "{said}");
    }

    #[test]
    fn without_a_cli_reference_the_interrupting_steps_on_an_agent_are_blocked() {
        // D7: no fallback. The guests would be interrupted without being
        // moved, so the step says so instead of happening.
        let (release, observation) = upgrade(&["n1"], false);
        let careful = plan(
            &release,
            "host=n1",
            &observation,
            None,
            &PlanPolicy::new(PlanKind::Upgrade),
            at(NOW),
        )
        .unwrap();
        let plan = careful;
        let why = action(&plan, "n1", ActionKind::Drain)
            .blocked
            .clone()
            .unwrap_or_default();
        assert!(why.contains("cli_config"), "{why}");
        assert!(action(&plan, "n1", ActionKind::Cordon).blocked.is_some());
        assert!(action(&plan, "n1", ActionKind::Activate).is_blocked());
        // Staging is not an interruption and stays allowed.
        assert!(!action(&plan, "n1", ActionKind::Stage).is_blocked());
    }

    #[test]
    fn a_host_nobody_looked_at_stays_in_the_plan_and_is_listed() {
        let (release, observation) = upgrade(&["n1"], false);
        let mut observation = observation;
        observation.hosts.remove("n1");
        let plan = planned(&release, "all", &observation);
        assert!(plan.selection.targets.contains(&"n1".to_string()));
        assert_eq!(plan.selection.required_unreachable, ["n1"]);
        assert_eq!(plan.hosts["n1"].verdict, HostVerdict::Unreachable);
        assert!(action(&plan, "n1", ActionKind::Activate).is_blocked());
    }

    #[test]
    fn a_host_that_did_not_answer_is_unreachable_and_not_unchanged() {
        let (release, observation) = upgrade(&["n1"], false);
        let mut observation = observation;
        let n1 = observation.hosts.get_mut("n1").unwrap();
        *n1 = crate::observation::HostObservation::unreachable("the connection timed out");
        let plan = planned(&release, "host=n1", &observation);
        assert_eq!(plan.hosts["n1"].verdict, HostVerdict::Unreachable);
        assert_eq!(plan.selection.required_unreachable, ["n1"]);
    }

    #[test]
    fn a_context_host_is_refused_by_name_rather_than_planned_for() {
        let mut base = onebox_enrolled();
        base.hosts.get_mut("n2").unwrap().deployment = crate::manifest::Deployment::Context;
        base.manifest_id = content_id(IdKind::Manifest, &base).unwrap();
        let running = release_of(base.clone());
        let observation = observed(&running, at(TAKEN));
        let release = with_new_systems(base, &["n2"], false);
        let plan = planned(&release, "host=n2", &observation);
        let why = &plan.hosts["n2"].reasons[0];
        assert!(why.contains("deployed as `context`"), "{why}");
        // The sentence has to name where the push lives NOW. `src/legacy/`
        // and the verb `legacy push` went with M5B; a host of the context
        // fleet is served from the lab repository, and a refusal that
        // pointed at a verb this binary no longer has would send an
        // operator looking for it.
        assert!(why.contains("meisterstack-lab/legacy/push.sh"), "{why}");
    }

    #[test]
    fn an_operator_module_is_an_unknown_and_never_an_analysis() {
        let (release, observation) = upgrade(&["box"], false);
        let plan = planned(&release, "host=box", &observation);
        assert!(
            plan.unknowns.iter().any(|u| {
                u.host.as_deref() == Some("box")
                    && u.reason
                        .contains("operator module effects are not analysed")
            }),
            "{:?}",
            plan.unknowns
        );
    }

    // -----------------------------------------------------------------
    // Groups, quorum, topology, order
    // -----------------------------------------------------------------

    #[test]
    fn a_raft_group_of_one_is_a_singleton_and_says_so() {
        // V13.
        let (release, observation) = upgrade(&["box"], false);
        let plan = planned(&release, "host=box", &observation);
        assert!(plan.groups["box"].singleton);
        assert_eq!(plan.groups["box"].size, 1);
        assert_eq!(plan.groups["box"].allowed_unavailable, 0);
        assert!(plan.groups["box"].blocked.is_none());
        assert_eq!(
            action(&plan, "box", ActionKind::Activate).approval_class,
            ApprovalClass::Singleton
        );
        assert!(
            plan.approvals
                .iter()
                .any(|a| a.class == ApprovalClass::Singleton)
        );
    }

    #[test]
    fn an_approval_for_a_singleton_does_not_quietly_buy_a_reboot() {
        let (release, observation) = upgrade(&["box"], true);
        let plan = planned(&release, "host=box", &observation);
        let activate = action(&plan, "box", ActionKind::Activate);
        // The action shows the hardest class …
        assert_eq!(activate.approval_class, ApprovalClass::Singleton);
        // … and the gate is the union of what the steps need.
        let classes: Vec<ApprovalClass> = plan.approvals.iter().map(|a| a.class).collect();
        assert!(classes.contains(&ApprovalClass::Singleton), "{classes:?}");
        assert!(classes.contains(&ApprovalClass::Reboot), "{classes:?}");
    }

    #[test]
    fn every_approval_in_a_plan_is_bound_to_that_plan() {
        let (release, observation) = upgrade(&["box"], true);
        let plan = planned(&release, "host=box", &observation);
        assert!(!plan.approvals.is_empty());
        for approval in &plan.approvals {
            assert_eq!(approval.bound_plan_id, plan.plan_id);
            assert!(approval.granted_by.is_none());
        }
        assert!(plan.id_matches().unwrap());
    }

    #[test]
    fn a_degraded_raft_group_blocks_every_interruption_in_it() {
        // V14, in the three-member shape the arithmetic is about.
        let (release, observation) = three_member_cloud(1);
        let plan = planned(&release, "group=cloud", &observation);
        let view = &plan.groups["cloud"];
        assert_eq!(view.size, 3);
        assert_eq!(view.unhealthy_now, 1);
        assert_eq!(view.allowed_unavailable, 0);
        let why = view.blocked.clone().unwrap_or_default();
        assert!(why.contains("is at 2 of 3"), "{why}");
        assert!(why.contains("no further member may go down"), "{why}");
        for host in ["cloud-a", "cloud-b"] {
            assert!(action(&plan, host, ActionKind::Activate).is_blocked());
        }
    }

    #[test]
    fn a_healthy_raft_group_may_lose_one_member_and_exactly_one() {
        let (release, observation) = three_member_cloud(0);
        let plan = planned(&release, "group=cloud", &observation);
        assert_eq!(plan.groups["cloud"].allowed_unavailable, 1);
        assert_eq!(plan.groups["cloud"].unhealthy_now, 0);
        // Three members, three waves: strictly one at a time.
        let waves: Vec<u32> = ["cloud-a", "cloud-b", "cloud-c"]
            .iter()
            .map(|h| plan.hosts[*h].wave)
            .collect();
        assert_eq!(waves, [0, 1, 2], "one member of a raft group per wave");
    }

    #[test]
    fn a_member_with_no_etcd_answer_counts_as_unavailable_and_is_an_unknown() {
        let (release, mut observation) = three_member_cloud(0);
        observation.hosts.get_mut("cloud-c").unwrap().etcd = None;
        let plan = planned(&release, "group=cloud", &observation);
        assert_eq!(plan.groups["cloud"].unhealthy_now, 1);
        assert!(plan.groups["cloud"].blocked.is_some());
        assert!(
            plan.unknowns
                .iter()
                .any(|u| u.reason.contains("no etcd answer")),
            "{:?}",
            plan.unknowns
        );
    }

    #[test]
    fn an_etcd_that_is_not_running_yet_does_not_block_a_bootstrap() {
        // Found in the lab (lane L2, 2026-09-23): a fresh managed image
        // carries the etcd unit without starting it, so the probe answered
        // `EtcdView { healthy: false, members: [] }` for every host of the
        // group — `observe::etcd_view`'s deliberate shape for "this member
        // is down". `topology_verdict` read that as "etcd answered and does
        // not know you" and blocked activate, reboot and confirm on the one
        // box the bootstrap was supposed to bring up.
        //
        // A view with no members at all says nothing about membership, and
        // a bootstrap is precisely the case where nothing can have.
        let (release, mut observation) = three_member_cloud(0);
        for host in observation.hosts.values_mut() {
            if let Some(etcd) = host.etcd.as_mut() {
                etcd.healthy = false;
                etcd.member_id = None;
                etcd.members.clear();
            }
        }
        let plan = planned(&release, "group=cloud", &observation);
        let why = plan.groups["cloud"].blocked.clone().unwrap_or_default();
        assert!(
            !why.contains("migration sequence this tool does not have"),
            "an etcd that is not running yet is not a membership change: {why}"
        );
    }

    #[test]
    fn a_membership_that_is_not_the_declared_one_blocks_the_whole_group() {
        let (release, mut observation) = three_member_cloud(0);
        for host in observation.hosts.values_mut() {
            if let Some(etcd) = host.etcd.as_mut() {
                etcd.members.push(crate::observation::EtcdMember {
                    id: "stranger-id".to_string(),
                    name: "cloud-d".to_string(),
                    peer_urls: vec!["https://10.0.9.9:2380".to_string()],
                    healthy: true,
                });
            }
        }
        let plan = planned(&release, "group=cloud", &observation);
        let why = plan.groups["cloud"].blocked.clone().unwrap_or_default();
        assert!(why.contains("cloud-d"), "{why}");
        assert!(
            why.contains("migration sequence this tool does not have"),
            "{why}"
        );
    }

    #[test]
    fn a_member_that_moved_blocks_the_group_too() {
        let (release, mut observation) = three_member_cloud(0);
        observation
            .hosts
            .get_mut("cloud-b")
            .unwrap()
            .etcd
            .as_mut()
            .unwrap()
            .members
            .iter_mut()
            .for_each(|m| {
                if m.name == "cloud-b" {
                    m.peer_urls = vec!["https://10.0.9.9:2380".to_string()];
                }
            });
        let plan = planned(&release, "group=cloud", &observation);
        let why = plan.groups["cloud"].blocked.clone().unwrap_or_default();
        assert!(why.contains("advertises"), "{why}");
        assert!(why.contains("10.0.9.9"), "{why}");
    }

    #[test]
    fn a_group_that_is_degraded_but_can_still_afford_one_asks_for_a_quorum_approval() {
        let (release, observation) = five_member_cloud(1);
        let plan = planned(&release, "group=cloud", &observation);
        assert_eq!(plan.groups["cloud"].size, 5);
        assert_eq!(plan.groups["cloud"].unhealthy_now, 1);
        assert_eq!(plan.groups["cloud"].allowed_unavailable, 1);
        assert!(plan.groups["cloud"].blocked.is_none());
        assert_eq!(
            action(&plan, "cloud-a", ActionKind::Activate).approval_class,
            ApprovalClass::Quorum
        );
    }

    #[test]
    fn a_node_goes_forward_before_the_node_that_gives_it_orders() {
        let (release, observation) = upgrade(&["box", "n1", "n2"], false);
        let plan = planned(&release, "all", &observation);
        // box is cluster and cloud; n1 and n2 report to it.
        assert!(
            plan.hosts["box"].wave > plan.hosts["n1"].wave,
            "box {} n1 {}",
            plan.hosts["box"].wave,
            plan.hosts["n1"].wave
        );
        assert!(plan.hosts["box"].wave > plan.hosts["n2"].wave);
        let deps = &action(&plan, "box", ActionKind::Activate).depends_on;
        let on: Vec<&str> = deps.iter().map(|d| d.host.as_str()).collect();
        assert_eq!(on, ["n1", "n2"]);
        assert!(
            deps[0].reason.contains("gives orders to n1"),
            "{}",
            deps[0].reason
        );
    }

    #[test]
    fn a_bootstrap_turns_the_order_around_and_delivers_the_secrets_first() {
        let base = onebox_enrolled();
        let running = release_of(base.clone());
        let mut observation = observed(&running, at(TAKEN));
        for host in observation.hosts.values_mut() {
            host.enrolled = false;
            host.credentials.values_mut().for_each(|v| *v = None);
        }
        let release = with_new_systems(base, &["box", "n1", "n2"], false);
        let bootstrapped = plan(
            &release,
            "all",
            &observation,
            None,
            &plan_policy_with_certificates(PlanKind::Bootstrap, &release.resolved_fleet),
            at(NOW),
        )
        .unwrap();
        let plan = bootstrapped;

        assert!(
            plan.hosts["box"].wave < plan.hosts["n1"].wave,
            "the prerequisite stands before the dependant looks for it"
        );
        let steps = kinds(&plan, "box");
        let deliver = steps
            .iter()
            .position(|k| *k == ActionKind::DeliverSecret)
            .expect("a bootstrap delivers secrets");
        let activate = steps
            .iter()
            .position(|k| *k == ActionKind::Activate)
            .expect("and activates afterwards");
        assert!(deliver < activate, "{steps:?}");
        // The identity key is made on the target, so it never travels.
        let delivered: Vec<&str> = plan
            .actions_for("box")
            .into_iter()
            .filter(|a| a.kind == ActionKind::DeliverSecret)
            .filter_map(|a| a.desired.as_deref())
            .collect();
        assert!(
            !delivered.iter().any(|d| d.starts_with("identity ")),
            "{delivered:?}"
        );
        assert!(
            delivered.iter().any(|d| d.starts_with("ca-bundle ")),
            "{delivered:?}"
        );
    }

    #[test]
    fn a_host_with_three_roles_is_one_interruption_and_gets_one_activate() {
        let (release, observation) = upgrade(&["box"], false);
        let plan = planned(&release, "all", &observation);
        assert_eq!(
            plan.actions_for("box")
                .iter()
                .filter(|a| a.kind == ActionKind::Activate)
                .count(),
            1
        );
        // and it is not waiting for itself
        assert!(
            action(&plan, "box", ActionKind::Activate)
                .depends_on
                .iter()
                .all(|d| d.host != "box")
        );
    }

    #[test]
    fn a_class_gets_one_canary_and_the_rest_comes_after_it() {
        let (release, observation) = upgrade(&["n1", "n2"], false);
        let plan = planned(&release, "all", &observation);
        assert!(plan.hosts["n1"].canary, "the first of the class by id");
        assert!(!plan.hosts["n2"].canary);
        assert_eq!(plan.hosts["n1"].class, "compute-cpu");
        assert_eq!(plan.hosts["n2"].class, "compute-cpu");
        assert!(
            plan.hosts["n2"].wave > plan.hosts["n1"].wave,
            "n1 {} n2 {}",
            plan.hosts["n1"].wave,
            plan.hosts["n2"].wave
        );
    }

    #[test]
    fn a_class_nobody_declared_is_derived_from_what_the_hosts_actually_are() {
        let mut base = onebox_enrolled();
        for host in base.hosts.values_mut() {
            host.rollout.canary_class = None;
        }
        base.manifest_id = content_id(IdKind::Manifest, &base).unwrap();
        let running = release_of(base.clone());
        let observation = observed(&running, at(TAKEN));
        let release = with_new_systems(base, &["n1", "n2"], false);
        let plan = planned(&release, "host=n1,host=n2", &observation);
        assert_eq!(plan.hosts["n1"].class, plan.hosts["n2"].class);
        assert!(
            plan.hosts["n1"]
                .class
                .starts_with("derived:6.12.41|base+compute-cpu|"),
            "{}",
            plan.hosts["n1"].class
        );
    }

    #[test]
    fn a_cycle_is_an_error_and_not_a_host_that_never_gets_a_wave() {
        // The tier edges cannot make one, so the sorter is asked directly —
        // which is the thing that has to stay safe when somebody adds an edge.
        let mut edges: BTreeMap<String, Vec<Dependency>> = BTreeMap::new();
        edges.insert(
            "a".to_string(),
            vec![Dependency {
                host: "b".to_string(),
                reason: "for the test".to_string(),
            }],
        );
        edges.insert(
            "b".to_string(),
            vec![Dependency {
                host: "a".to_string(),
                reason: "for the test".to_string(),
            }],
        );
        let (release, observation) = upgrade(&["n1"], false);
        let decisions: BTreeMap<String, HostDecision> = ["a", "b"]
            .iter()
            .map(|id| {
                (
                    (*id).to_string(),
                    decide_host(
                        &release,
                        "n1",
                        &observation,
                        &BTreeMap::new(),
                        &plan_policy(PlanKind::Upgrade),
                    ),
                )
            })
            .collect();
        let err = topological(&["a".to_string(), "b".to_string()], &decisions, &edges)
            .unwrap_err()
            .to_string();
        assert!(err.contains("wait for each other"), "{err}");
    }

    // -----------------------------------------------------------------
    // The plan as a whole
    // -----------------------------------------------------------------

    #[test]
    fn the_same_inputs_are_the_same_plan_id() {
        let (release, observation) = upgrade(&["n1", "n2"], false);
        let first = planned(&release, "all", &observation);
        let second = super::plan(
            &release,
            "all",
            &observation,
            None,
            &plan_policy(PlanKind::Upgrade),
            // A different afternoon, the same question.
            at("2026-09-22T08:30:00Z"),
        )
        .unwrap();
        assert_eq!(first.plan_id, second.plan_id);
        assert_ne!(first.created_at, second.created_at);
        assert_ne!(first.expires_at, second.expires_at);

        // A different observation is a different plan.
        let mut moved = observation.clone();
        moved.hosts.get_mut("n2").unwrap().generation = Some(43);
        assert_ne!(first.plan_id, planned(&release, "all", &moved).plan_id);
    }

    #[test]
    fn the_selection_is_written_down_and_not_re_evaluated() {
        let (release, observation) = upgrade(&["n1"], false);
        let plan = planned(&release, "role=agent,!host=box", &observation);
        assert_eq!(plan.selection.targets, ["n1", "n2"]);
        assert_eq!(plan.selection.expr, "role=agent,!host=box");
        // Every action belongs to a host of the frozen set.
        for a in &plan.actions {
            assert!(plan.selection.targets.contains(&a.host), "{}", a.host);
        }
    }

    #[test]
    fn a_plan_expires_and_says_when() {
        let (release, observation) = upgrade(&["n1"], false);
        let plan = planned(&release, "host=n1", &observation);
        assert_eq!(
            plan.expires_at - plan.created_at,
            chrono::TimeDelta::seconds(DEFAULT_VALIDITY_SECS as i64)
        );
    }

    #[test]
    fn a_plan_reads_back_from_its_own_json_and_notices_an_edit() {
        let (release, observation) = upgrade(&["n1"], false);
        let plan = planned(&release, "host=n1", &observation);
        let text = String::from_utf8(plan.to_json().unwrap()).unwrap();
        assert_eq!(
            DeploymentPlan::from_json(&text, "the round trip").unwrap(),
            plan
        );

        let mut value: serde_json::Value = serde_json::from_str(&text).unwrap();
        value["actions"][0]["wave"] = serde_json::json!(9);
        let err = DeploymentPlan::from_json(&serde_json::to_string(&value).unwrap(), "the edit")
            .unwrap_err()
            .to_string();
        assert!(err.contains("edited after it was planned"), "{err}");
    }

    #[test]
    fn the_plan_carries_where_each_host_is_reached() {
        let (release, observation) = upgrade(&["n1"], false);
        let plan = planned(&release, "host=n1", &observation);
        assert_eq!(plan.endpoints["n1"].address, "10.0.0.11");
        assert_eq!(plan.endpoints["n1"].port, 22);
        assert!(plan.endpoints["n1"].provider_ref.is_none());
    }

    #[test]
    fn a_release_that_did_not_build_a_selected_host_is_refused() {
        let (mut release, observation) = upgrade(&["n1"], false);
        release.artifacts.remove("n2");
        let err = super::plan(
            &release,
            "all",
            &observation,
            None,
            &plan_policy(PlanKind::Upgrade),
            at(NOW),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("no artifacts for n2"), "{err}");
    }

    #[test]
    fn an_offline_plan_knows_nothing_and_interrupts_nothing() {
        let (release, _) = upgrade(&["n1"], false);
        let nothing = Observations::provisional(at(TAKEN));
        let plan = planned(&release, "all", &nothing);
        assert!(plan.observation.provisional);
        assert!(
            plan.unknowns
                .iter()
                .any(|u| u.reason.contains("provisional observation")),
            "{:?}",
            plan.unknowns
        );
        for host in plan.hosts.values() {
            assert_eq!(host.verdict, HostVerdict::Blocked);
        }
        for a in &plan.actions {
            if a.disruption != Disruption::None {
                let why = a.blocked.clone().unwrap_or_default();
                assert!(why.contains("needs an online observation"), "{why}");
            }
        }
        assert!(plan.approvals.is_empty());
        assert_eq!(plan.groups.len(), 2, "the groups are still named");
    }

    /// A three-member raft group, `unhealthy` of whose members are down.
    fn three_member_cloud(unhealthy: usize) -> (ReleaseManifest, Observations) {
        raft_cloud(3, unhealthy)
    }

    fn five_member_cloud(unhealthy: usize) -> (ReleaseManifest, Observations) {
        raft_cloud(5, unhealthy)
    }

    /// The one-box fixture with its `box` group grown into a real raft group:
    /// `size` cloud controllers, `unhealthy` of them not answering etcd.
    fn raft_cloud(size: usize, unhealthy: usize) -> (ReleaseManifest, Observations) {
        let mut fleet = onebox_enrolled();
        let template = fleet.hosts["box"].clone();
        let group = fleet
            .groups
            .get_mut("box")
            .expect("the fixture's raft group")
            .clone();
        fleet.groups.remove("box");
        fleet.hosts.remove("box");
        fleet.hosts.remove("n1");
        fleet.hosts.remove("n2");

        let members: Vec<String> = (0..size)
            .map(|i| format!("cloud-{}", (b'a' + i as u8) as char))
            .collect();
        let peers: Vec<String> = members
            .iter()
            .enumerate()
            .map(|(i, m)| format!("{m}=https://10.0.1.{}:2380", 10 + i))
            .collect();
        for (i, id) in members.iter().enumerate() {
            let mut host = template.clone();
            host.name = id.clone();
            host.address = format!("10.0.1.{}", 10 + i);
            host.roles = vec!["cloud".to_string(), "cluster".to_string()];
            host.groups = vec!["cloud".to_string()];
            host.ssh.host_key_fingerprint = Some(format!("SHA256:enrolled-{id}"));
            host.modules = Vec::new();
            host.rollout.canary_class = Some("controller".to_string());
            host.effective_settings.etcd = Some(serde_json::json!({
                "name": id,
                "initial_cluster": peers.join(","),
            }));
            host.build.toplevel_drv = format!("/nix/store/base{id}-nixos-system-{id}.drv");
            host.build.toplevel_out = format!("/nix/store/base{id}-nixos-system-{id}");
            fleet.hosts.insert(id.clone(), host);
        }
        let mut group = group;
        group.members = members.clone();
        group.quorum = Some(crate::manifest::Quorum { size: size as u32 });
        group.rollout.canary_class = Some("controller".to_string());
        fleet.groups.insert("cloud".to_string(), group);
        fleet.evaluated_hosts = fleet.hosts.keys().cloned().collect();
        fleet.manifest_id = content_id(IdKind::Manifest, &fleet).unwrap();

        let running = release_of(fleet.clone());
        let mut observation = observed(&running, at(TAKEN));
        for id in members.iter().rev().take(unhealthy) {
            let host = observation.hosts.get_mut(id).expect("a member");
            host.etcd.as_mut().expect("a raft member").healthy = false;
            for other in observation.hosts.values_mut() {
                if let Some(etcd) = other.etcd.as_mut() {
                    for m in &mut etcd.members {
                        if &m.name == id {
                            m.healthy = false;
                        }
                    }
                }
            }
        }
        let refs: Vec<&str> = members.iter().map(String::as_str).collect();
        (with_new_systems(fleet, &refs, false), observation)
    }

    // -----------------------------------------------------------------
    // validate_against
    // -----------------------------------------------------------------

    /// A plan over the one-box fleet, and the fresh snapshot `apply` would
    /// take a moment later — identical until a test moves something.
    fn about_to_apply() -> (ReleaseManifest, DeploymentPlan, Observations) {
        let (release, observation) = upgrade(&["n1"], false);
        let plan = planned(&release, "host=n1", &observation);
        let fresh = observation;
        (release, plan, fresh)
    }

    fn later() -> DateTime<Utc> {
        at("2026-09-21T12:05:00Z")
    }

    #[test]
    fn a_fleet_that_did_not_move_lets_the_plan_proceed() {
        let (release, plan, fresh) = about_to_apply();
        assert_eq!(
            validate_against(&plan, &release, &fresh, later()),
            Verdict::Proceed
        );
    }

    #[test]
    fn another_release_stops_the_run_before_anything_is_compared() {
        let (_, plan, fresh) = about_to_apply();
        let (other, _) = upgrade(&["n2"], false);
        let verdict = validate_against(&plan, &other, &fresh, later());
        assert!(matches!(verdict, Verdict::Stop { .. }));
        assert!(verdict.reasons()[0].contains("another build is another plan"));
    }

    #[test]
    fn an_artifact_that_moved_under_the_plan_stops_the_run() {
        // V12: the store path is the same and the bytes are not.
        let (mut release, plan, fresh) = about_to_apply();
        release.artifacts.get_mut("n1").unwrap().toplevel.nar_hash = "sha256:rebuilt".to_string();
        // The release id is recomputed the way a rebuild would produce one,
        // so the check has to catch the artifact and not the id.
        release.release_id = plan.release_id.clone();
        let verdict = validate_against(&plan, &release, &fresh, later());
        assert!(matches!(verdict, Verdict::Stop { .. }));
        assert!(
            verdict.reasons()[0].contains("Same name, different bytes"),
            "{:?}",
            verdict.reasons()
        );
    }

    #[test]
    fn an_expired_plan_is_made_again_and_not_run() {
        let (release, plan, fresh) = about_to_apply();
        let verdict = validate_against(&plan, &release, &fresh, at("2026-09-21T14:00:00Z"));
        assert!(matches!(verdict, Verdict::Replan { .. }), "{verdict:?}");
        assert!(verdict.reasons()[0].contains("expired at"));
    }

    #[test]
    fn an_identity_that_changed_between_plan_and_apply_stops_the_run() {
        let (release, plan, mut fresh) = about_to_apply();
        fresh
            .hosts
            .get_mut("n1")
            .unwrap()
            .identity
            .host_key_fingerprint = Some("SHA256:somebody-else".to_string());
        let verdict = validate_against(&plan, &release, &fresh, later());
        assert!(matches!(verdict, Verdict::Stop { .. }));
        assert!(verdict.reasons()[0].contains("identity changed"));
    }

    #[test]
    fn a_machine_id_that_changed_stops_the_run_too() {
        let (release, plan, mut fresh) = about_to_apply();
        fresh.hosts.get_mut("n1").unwrap().identity.machine_id = Some("reinstalled".to_string());
        let verdict = validate_against(&plan, &release, &fresh, later());
        assert!(matches!(verdict, Verdict::Stop { .. }));
        assert!(verdict.reasons()[0].contains("not the same installation"));
    }

    #[test]
    fn somebody_elses_deployment_asks_for_a_new_plan() {
        let (release, plan, mut fresh) = about_to_apply();
        let n1 = fresh.hosts.get_mut("n1").unwrap();
        n1.current_system = Some("/nix/store/somebody-elses-system".to_string());
        n1.generation = Some(43);
        let verdict = validate_against(&plan, &release, &fresh, later());
        assert!(matches!(verdict, Verdict::Replan { .. }), "{verdict:?}");
        assert_eq!(verdict.reasons().len(), 2);
        assert!(verdict.reasons()[0].contains("somebody deployed to it"));
        assert!(verdict.reasons()[1].contains("generation of n1 moved"));
    }

    #[test]
    fn a_lock_that_appeared_in_the_meantime_stops_the_run() {
        let (release, plan, mut fresh) = about_to_apply();
        fresh.hosts.get_mut("n1").unwrap().lock = Some(Lock {
            run_id: "0192-other".to_string(),
            operator: "somebody".to_string(),
            pid: 9,
            acquired_at: at("2026-09-21T12:01:00Z"),
        });
        let verdict = validate_against(&plan, &release, &fresh, later());
        assert!(matches!(verdict, Verdict::Stop { .. }));
        assert!(verdict.reasons()[0].contains("0192-other"));
    }

    #[test]
    fn a_transaction_that_appeared_in_the_meantime_stops_the_run() {
        let (release, plan, mut fresh) = about_to_apply();
        fresh.hosts.get_mut("n1").unwrap().open_txns = vec![Txn {
            id: "txn-9".to_string(),
            state: TxnState::Pending,
            target_system: None,
            deadline: None,
            run_id: None,
        }];
        let verdict = validate_against(&plan, &release, &fresh, later());
        assert!(matches!(verdict, Verdict::Stop { .. }));
        assert!(verdict.reasons()[0].contains("txn-9"));
    }

    #[test]
    fn a_host_that_stopped_answering_stops_the_run() {
        let (release, plan, mut fresh) = about_to_apply();
        fresh.hosts.get_mut("n1").unwrap().reachable = false;
        let verdict = validate_against(&plan, &release, &fresh, later());
        assert!(matches!(verdict, Verdict::Stop { .. }));
        assert!(verdict.reasons()[0].contains("does not answer any more"));
    }

    #[test]
    fn a_quorum_that_got_worse_stops_the_run() {
        let (release, mut observation) = three_member_cloud(0);
        let plan = planned(&release, "group=cloud", &observation);
        assert!(validate_against(&plan, &release, &observation, later()).is_proceed());

        observation
            .hosts
            .get_mut("cloud-c")
            .unwrap()
            .etcd
            .as_mut()
            .unwrap()
            .healthy = false;
        let verdict = validate_against(&plan, &release, &observation, later());
        assert!(matches!(verdict, Verdict::Stop { .. }), "{verdict:?}");
        assert!(
            verdict
                .reasons()
                .iter()
                .any(|r| r.contains("It could when this plan was made")),
            "{:?}",
            verdict.reasons()
        );
    }

    #[test]
    fn a_provisional_snapshot_never_confirms_a_plan() {
        let (release, plan, _) = about_to_apply();
        let nothing = Observations::provisional(later());
        let verdict = validate_against(&plan, &release, &nothing, later());
        assert!(matches!(verdict, Verdict::Stop { .. }));
        assert!(
            verdict.reasons().iter().any(|r| r.contains("provisional")),
            "{:?}",
            verdict.reasons()
        );
    }

    #[test]
    fn a_host_the_plan_already_blocked_is_not_re_litigated() {
        // n2 is unenrolled in the raw fixture, so the plan blocked it. That
        // it is still unenrolled at apply time is not a reason to stop the
        // hosts that are fine.
        let base = onebox();
        let running = release_of(base.clone());
        let observation = observed(&running, at(TAKEN));
        let release = with_new_systems(base, &["n1", "n2"], false);
        let plan = planned(&release, "host=n1,host=n2", &observation);
        assert_eq!(plan.hosts["n2"].verdict, HostVerdict::Unenrolled);
        assert!(validate_against(&plan, &release, &observation, later()).is_proceed());
    }

    #[test]
    fn a_label_added_afterwards_never_adds_a_host_to_a_frozen_plan() {
        // The selection is a list, not an expression to evaluate again. A
        // host that appears in the fresh snapshot — however broken — is not
        // in this plan and does not stop it.
        let (release, plan, mut fresh) = about_to_apply();
        assert_eq!(plan.selection.targets, ["n1"]);
        fresh.hosts.insert(
            "newcomer".to_string(),
            crate::observation::HostObservation::unreachable("it is on fire"),
        );
        assert!(validate_against(&plan, &release, &fresh, later()).is_proceed());
        assert_eq!(plan.selection.targets, ["n1"], "still just n1");
    }

    // -----------------------------------------------------------------
    // approvals
    // -----------------------------------------------------------------

    #[test]
    fn an_approval_for_another_plan_does_not_count() {
        let (release, observation) = upgrade(&["box"], true);
        let plan = planned(&release, "host=box", &observation);
        let classes: Vec<ApprovalClass> = plan.approvals.iter().map(|a| a.class).collect();
        assert!(classes.contains(&ApprovalClass::Reboot));

        assert_eq!(approvals_missing(&plan, &[]), classes);
        assert_eq!(
            approvals_missing(
                &plan,
                &[(ApprovalClass::Reboot, "plan-from-yesterday".to_string())]
            ),
            classes,
            "a grant for another plan approves that other plan"
        );
        let all: Vec<(ApprovalClass, String)> =
            classes.iter().map(|c| (*c, plan.plan_id.clone())).collect();
        assert!(approvals_missing(&plan, &all).is_empty());
    }

    #[test]
    fn a_plan_that_needs_nothing_asks_for_nothing() {
        let (release, observation) = upgrade(&["n1"], false);
        let plan = planned(&release, "host=n1", &observation);
        // A plain switch on a compute host: disruptive, and that is all.
        assert_eq!(
            plan.approvals.iter().map(|a| a.class).collect::<Vec<_>>(),
            [ApprovalClass::Disruptive]
        );
    }

    #[test]
    fn an_approval_class_reads_back_from_what_it_prints() {
        for class in [
            ApprovalClass::None,
            ApprovalClass::Disruptive,
            ApprovalClass::Quorum,
            ApprovalClass::Reboot,
            ApprovalClass::Singleton,
            ApprovalClass::Destructive,
        ] {
            assert_eq!(ApprovalClass::parse(class.as_str()).unwrap(), class);
        }
        let err = ApprovalClass::parse("whatever").unwrap_err().to_string();
        assert!(err.contains("disruptive"), "{err}");
    }
}

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
    Verify,
    Confirm,
    Uncordon,
    Unlock,
    Install,
    Revoke,
    Gc,
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
            ActionKind::Verify => "verify",
            ActionKind::Confirm => "confirm",
            ActionKind::Uncordon => "uncordon",
            ActionKind::Unlock => "unlock",
            ActionKind::Install => "install",
            ActionKind::Revoke => "revoke",
            ActionKind::Gc => "gc",
        }
    }

    /// Whether this step, once begun, cannot be taken back by this tool.
    /// The journal writes `action.irreversible` before exactly these, and a
    /// resume never repeats one blind (V17).
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
}

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
}

impl PlanPolicy {
    pub fn new(kind: PlanKind) -> PlanPolicy {
        PlanPolicy {
            kind,
            valid_for_secs: DEFAULT_VALIDITY_SECS,
            workload_control: None,
            confirm_within_switch_secs: CONFIRM_WITHIN_SWITCH_SECS,
            confirm_within_boot_secs: CONFIRM_WITHIN_BOOT_SECS,
        }
    }

    pub fn with_workload_control(mut self, control: Option<WorkloadControl>) -> PlanPolicy {
        self.workload_control = control;
        self
    }
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

    let mut d = HostDecision {
        verdict: HostVerdict::Change,
        reasons: Vec::new(),
        stop_all: Vec::new(),
        stop_disruptive: Vec::new(),
        current_system: None,
        reboot_required: false,
        reboot_only: false,
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
             binaries are pushed, so a closure is not how it is taken forward. \
             `meister-deploy legacy context-push` carries it until the context fleet is \
             migrated."
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
    for capability in &host.hardware.capabilities {
        if obs.has_capability(capability) {
            d.preconditions.push(format!("{id} has {capability}"));
        } else {
            d.stop_all.push(format!(
                "the fleet declares that {id} has {capability} and the snapshot did not find \
                 it. A host that is missing a declared capability cannot run what was built \
                 for it."
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
    d.needs_maintenance = !unchanged && host.roles.iter().any(|r| r == "agent");
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

    let verdict = if !d.stop_all.is_empty() {
        HostVerdict::Blocked
    } else if unchanged {
        HostVerdict::Unchanged
    } else if !d.stop_disruptive.is_empty() {
        HostVerdict::Blocked
    } else {
        HostVerdict::Change
    };
    if unchanged {
        d.reboot_required = false;
        d.needs_maintenance = false;
    }
    settle(d, verdict)
}

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
    if decision.verdict == HostVerdict::Unchanged {
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

        if policy.kind == PlanKind::Bootstrap {
            for secret in &host.secret_refs {
                // A key that was made on the target never travels. Delivering
                // one would mean this workstation had it, which is the whole
                // thing `meister-activate keygen` exists to avoid.
                if secret.source.kind == crate::manifest::SecretSourceKind::TargetGenerated {
                    continue;
                }
                let restarts = secret
                    .reload
                    .as_ref()
                    .map(|r| r.action == "restart")
                    .unwrap_or(false);
                specs.push(
                    step(
                        ActionKind::DeliverSecret,
                        if restarts {
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
                    .because(format!(
                        "a bootstrap puts {} in place before the system that reads it is \
                         activated",
                        secret.id
                    )),
                );
            }
        }

        if !decision.reboot_only {
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

        if decision.reboot_only {
            specs.push(
                step(ActionKind::Reboot, Disruption::Reboot)
                    .maybe_from(obs.and_then(|o| o.booted_system.clone()))
                    .to(desired.clone())
                    .because(
                        "this system was switched to and never booted, so there is nothing to \
                         activate and nothing to take back: if it does not come up, the way \
                         back is the boot menu",
                    ),
            );
        } else {
            specs.push(
                step(ActionKind::Activate, Disruption::Service)
                    .maybe_from(decision.current_system.clone())
                    .to(desired.clone())
                    .because(if decision.reboot_required {
                        "the boot half of this release changed, so the profile is moved and the \
                         new system takes over at the next boot (--mode boot)"
                    } else {
                        "nothing in the boot half changed, so this takes effect at once \
                         (--mode switch)"
                    }),
            );
            if decision.reboot_required {
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
        if !decision.reboot_only {
            specs.push(
                step(ActionKind::Confirm, Disruption::None)
                    .to("the activation is kept")
                    .because(
                        "until this runs the target reverts on its own timer, which is what \
                         makes an activation survivable from a workstation that lost the link",
                    ),
            );
        }
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
    let carries_edges = if decision.reboot_only {
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
            && matches!(spec.kind, ActionKind::Activate | ActionKind::Reboot);
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
            validity: validity_for(spec.kind, id, host, obs, artifacts, groups),
            blocked,
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
        && matches!(kind, ActionKind::Activate | ActionKind::Reboot)
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
    let wants_identity = matches!(kind, Preflight | DeliverSecret | Activate | Install);
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
    if matches!(kind, Cordon | Drain | Activate | Reboot) {
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

    use crate::fixtures::{observed, onebox_enrolled, plan_policy, release_of, with_new_systems};
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
        observation.hosts.get_mut("n2").unwrap().enrolled = false;
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
            &plan_policy(PlanKind::Bootstrap),
            at(NOW),
        )
        .unwrap();
        assert_eq!(bootstrapped.hosts["n2"].verdict, HostVerdict::Change);
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
        assert!(why.contains("legacy context-push"), "{why}");
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
            &plan_policy(PlanKind::Bootstrap),
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

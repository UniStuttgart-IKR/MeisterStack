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
use crate::observation::{Endpoint, Observations};

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
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
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
        f.write_str(self.as_str())
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

impl std::fmt::Display for ApprovalClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
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
        f.write_str(self.as_str())
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
                content_id(IdKind::Plan, &plan)?
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
        Ok(content_id(IdKind::Plan, self)? == self.plan_id)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::onebox;

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
}

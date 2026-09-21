// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The last contract: what happened, and how a run that was cut in half
//! finds out where it was.
//!
//! Two files. The **journal** is append-only JSONL, one line per event,
//! `fsync`ed before the next line is written and — this is the whole point —
//! written BEFORE anything irreversible, never after. The **receipt** is the
//! fold of that journal into the answer somebody attaches to a ticket: which
//! host ended where, what it ran before, what it runs now, which certificate
//! it carries.
//!
//! [`fold`] and [`next_step`] are pure, and they are the two functions that
//! decide what a resume does. The V17 matrix — the thing that decides
//! whether an interrupted run repeats a step, continues past it, or refuses
//! to touch the host at all — is a table here and a test beside it, because
//! the alternative is discovering the rule on a machine that is halfway
//! through an activation.
//!
//! The rule that shapes the whole table: **an irreversible step that began
//! and has no end in the journal is never repeated.** The journal cannot say
//! what happened after the line it managed to write; the TARGET can, because
//! `meister-activate` keeps a transaction record. So the answer is always to
//! ask the target, and to say `recovery-required` when the target has
//! nothing to say — never to activate again and hope.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::checks::CheckResult;
use crate::observation::{HostObservation, TxnState};
use crate::plan::{ActionKind, DeploymentPlan, HostVerdict};

pub const RECEIPT_SCHEMA: &str = "meister-deploy/receipt/1";

// ---------------------------------------------------------------------------
// The journal
// ---------------------------------------------------------------------------

/// What a journal line is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum EventKind {
    #[serde(rename = "run.start")]
    RunStart,
    #[serde(rename = "lock.acquire")]
    LockAcquire,
    #[serde(rename = "lock.release")]
    LockRelease,
    #[serde(rename = "host.state")]
    HostState,
    #[serde(rename = "action.begin")]
    ActionBegin,
    /// Written BEFORE the step, and `fsync`ed. Everything about a resume
    /// hangs on this line being on the disk when the machine that was
    /// writing it goes away.
    #[serde(rename = "action.irreversible")]
    ActionIrreversible,
    #[serde(rename = "action.end")]
    ActionEnd,
    #[serde(rename = "run.end")]
    RunEnd,
}

/// One line of `journal.jsonl`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JournalEvent {
    /// From 1, strictly increasing. A gap is a lost line and is treated as
    /// one.
    pub seq: u64,
    pub ts: DateTime<Utc>,
    pub run_id: String,
    pub plan_id: String,
    pub event: EventKind,
    pub host: Option<String>,
    /// For `host.state`: the state it left.
    pub from: Option<String>,
    /// For `host.state`: the state it entered.
    pub to: Option<String>,
    /// Everything else. An object, always — see [`ActionPayload`] and
    /// [`StatePayload`] for the keys [`fold`] reads. A producer may put more
    /// in it; nothing here will drop a key it does not know.
    pub payload: serde_json::Value,
}

impl JournalEvent {
    pub fn new(
        seq: u64,
        ts: DateTime<Utc>,
        run_id: impl Into<String>,
        plan_id: impl Into<String>,
        event: EventKind,
    ) -> JournalEvent {
        JournalEvent {
            seq,
            ts,
            run_id: run_id.into(),
            plan_id: plan_id.into(),
            event,
            host: None,
            from: None,
            to: None,
            payload: serde_json::json!({}),
        }
    }

    pub fn host(mut self, host: impl Into<String>) -> JournalEvent {
        self.host = Some(host.into());
        self
    }

    pub fn transition(mut self, from: HostState, to: HostState) -> JournalEvent {
        self.from = Some(from.as_str().to_string());
        self.to = Some(to.as_str().to_string());
        self
    }

    pub fn payload(mut self, payload: serde_json::Value) -> JournalEvent {
        self.payload = payload;
        self
    }

    /// One line, compact, no trailing newline — [`crate::effects::Files::
    /// append_fsync`] adds that in the same write.
    pub fn to_line(&self) -> Result<String> {
        serde_json::to_string(self)
            .map_err(|e| anyhow::anyhow!("this journal entry could not be written: {e}"))
    }
}

/// Read a whole journal. Blank lines are skipped; a line that does not parse
/// is an error that says which line, because a journal is evidence and a
/// half-read one is worse than none.
pub fn parse_journal(text: &str, origin: &str) -> Result<Vec<JournalEvent>> {
    let mut out = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let event: JournalEvent = serde_json::from_str(line).map_err(|e| {
            anyhow::anyhow!("{origin} line {} is not a journal entry: {e}.", index + 1)
        })?;
        out.push(event);
    }
    Ok(out)
}

/// The keys [`fold`] reads out of a `host.state` payload.
#[derive(Debug, Clone, Default, Deserialize)]
struct StatePayload {
    #[serde(default)]
    system: Option<String>,
    #[serde(default)]
    generation: Option<u64>,
    #[serde(default)]
    booted: Option<String>,
}

/// The keys [`fold`] reads out of an `action.*` payload. This is the
/// contract lane 2C writes against.
#[derive(Debug, Clone, Deserialize)]
struct ActionPayload {
    /// The `seq` of the action IN THE PLAN, which is what lines a receipt up
    /// with the plan it came from.
    action: u32,
    kind: ActionKind,
    #[serde(default)]
    txn: Option<String>,
    #[serde(default)]
    result: Option<ActionResult>,
    #[serde(default)]
    evidence: Vec<String>,
    #[serde(default)]
    cmd_refs: Vec<String>,
    #[serde(default)]
    checks: Vec<CheckResult>,
    #[serde(default)]
    credentials: Option<CredentialVersions>,
}

#[derive(Debug, Clone, Deserialize)]
struct RunStartPayload {
    operator: Operator,
}

// ---------------------------------------------------------------------------
// States and outcomes
// ---------------------------------------------------------------------------

/// Where a host is in the machine of §6.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum HostState {
    Planned,
    Preflight,
    Blocked,
    /// The closure is on the host and the running system is untouched.
    Staged,
    /// Cordoned and drained: nothing of value is left to interrupt.
    MaintenanceReady,
    /// `action.irreversible` is on the disk and the target has a
    /// transaction.
    Activating,
    AwaitingReboot,
    Verifying,
    Committed,
    /// It went back, on purpose or by the target's own timer. The forward
    /// attempt stays failed.
    RolledBack,
    /// The link was lost. A resume asks the target rather than guessing.
    Unknown,
    /// Nobody may touch this host again without a person looking: the
    /// transaction record is missing or incoherent, or the host key changed.
    RecoveryRequired,
    Failed,
    /// It already ran what the release says. It was looked at and nothing
    /// else.
    Unchanged,
}

impl HostState {
    pub fn as_str(self) -> &'static str {
        match self {
            HostState::Planned => "planned",
            HostState::Preflight => "preflight",
            HostState::Blocked => "blocked",
            HostState::Staged => "staged",
            HostState::MaintenanceReady => "maintenance-ready",
            HostState::Activating => "activating",
            HostState::AwaitingReboot => "awaiting-reboot",
            HostState::Verifying => "verifying",
            HostState::Committed => "committed",
            HostState::RolledBack => "rolled-back",
            HostState::Unknown => "unknown",
            HostState::RecoveryRequired => "recovery-required",
            HostState::Failed => "failed",
            HostState::Unchanged => "unchanged",
        }
    }

    pub fn parse(text: &str) -> Result<HostState> {
        serde_json::from_value(serde_json::Value::String(text.to_string()))
            .map_err(|_| anyhow::anyhow!("{text:?} is not a host state this tool knows."))
    }

    /// Whether the journal says an irreversible step has begun on this host.
    fn past_the_point_of_no_return(self) -> bool {
        matches!(
            self,
            HostState::Activating
                | HostState::AwaitingReboot
                | HostState::Verifying
                | HostState::Committed
                | HostState::RolledBack
                | HostState::RecoveryRequired
        )
    }
}

impl std::fmt::Display for HostState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ActionResult {
    Ok,
    Failed,
    Skipped,
}

/// What a whole run came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Outcome {
    Success,
    Failed,
    /// Some hosts were taken forward and some were not.
    Partial,
    /// Nothing was taken forward and nothing broke: the run stopped.
    Aborted,
}

/// What one host came to. The five that are not `success` or `failed` are
/// the ones a two-valued outcome would have to lie about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum HostOutcome {
    Success,
    Failed,
    /// It already ran the release.
    Unchanged,
    /// The run ended before it got here at all.
    Unreached,
    /// The run touched it and left the running system alone: it was blocked,
    /// or it was prepared and never taken forward.
    Skipped,
    /// Nobody knows. Not a failure and never a success.
    Unknown,
    RolledBack,
    RecoveryRequired,
}

impl HostOutcome {
    fn of(state: HostState) -> HostOutcome {
        match state {
            HostState::Committed => HostOutcome::Success,
            HostState::Unchanged => HostOutcome::Unchanged,
            HostState::RolledBack => HostOutcome::RolledBack,
            HostState::RecoveryRequired => HostOutcome::RecoveryRequired,
            HostState::Failed => HostOutcome::Failed,
            HostState::Unknown => HostOutcome::Unknown,
            HostState::Blocked => HostOutcome::Skipped,
            HostState::Planned => HostOutcome::Unreached,
            // Reached, prepared, and the running system never moved.
            HostState::Preflight | HostState::Staged | HostState::MaintenanceReady => {
                HostOutcome::Skipped
            }
            // In the middle of an activation when the journal stopped.
            HostState::Activating | HostState::AwaitingReboot | HostState::Verifying => {
                HostOutcome::Unknown
            }
        }
    }

    fn is_failure(self) -> bool {
        matches!(
            self,
            HostOutcome::Failed | HostOutcome::RolledBack | HostOutcome::RecoveryRequired
        )
    }

    fn is_forward(self) -> bool {
        matches!(self, HostOutcome::Success | HostOutcome::Unchanged)
    }
}

// ---------------------------------------------------------------------------
// The fold
// ---------------------------------------------------------------------------

/// Who ran it, and from where.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Operator {
    pub user: String,
    pub workstation: String,
}

/// What a host ran, at one moment.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SystemView {
    pub system: Option<String>,
    pub generation: Option<u64>,
    pub booted: Option<String>,
}

impl SystemView {
    fn is_empty(&self) -> bool {
        self.system.is_none() && self.generation.is_none() && self.booted.is_none()
    }
}

/// Which credentials a host carried when the run ended. A receipt that does
/// not say this cannot answer "was the revoked certificate still in use".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CredentialVersions {
    pub identity_serial: Option<String>,
    pub ca_fingerprint: Option<String>,
    pub crl_number: Option<String>,
}

/// One step of one host, as it actually ran.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ActionRun {
    /// The `seq` it had in the plan.
    pub seq: u32,
    pub kind: ActionKind,
    pub started: DateTime<Utc>,
    pub ended: Option<DateTime<Utc>>,
    pub result: Option<ActionResult>,
    pub evidence: Vec<String>,
    pub cmd_refs: Vec<String>,
}

/// An irreversible step that began and has no end in the journal. The one
/// thing a resume may never repeat.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenAction {
    pub seq: u32,
    pub kind: ActionKind,
    pub started: DateTime<Utc>,
    pub txn: Option<String>,
}

/// What the journal says about one host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostRun {
    pub id: String,
    pub state: HostState,
    pub before: SystemView,
    pub after: SystemView,
    pub actions: Vec<ActionRun>,
    pub open_irreversible: Option<OpenAction>,
    pub txn_id: Option<String>,
    pub credential_versions: Option<CredentialVersions>,
    pub lock_held: bool,
}

impl HostRun {
    /// A host the journal says nothing about. What a resume starts from when
    /// the run died before it reached this host.
    pub fn new(id: impl Into<String>) -> HostRun {
        HostRun {
            id: id.into(),
            state: HostState::Planned,
            before: SystemView::default(),
            after: SystemView::default(),
            actions: Vec::new(),
            open_irreversible: None,
            txn_id: None,
            credential_versions: None,
            lock_held: false,
        }
    }
}

/// What the whole journal says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunState {
    pub run_id: String,
    pub plan_id: String,
    pub started_at: Option<DateTime<Utc>>,
    pub ended_at: Option<DateTime<Utc>>,
    pub operator: Option<Operator>,
    pub hosts: BTreeMap<String, HostRun>,
    pub last_seq: u64,
    pub checks: Vec<CheckResult>,
    /// Places where the journal does not add up: a gap in the sequence, a
    /// transition out of a state the host was not in. Not an error — a
    /// journal with a hole in it is evidence about a machine that went away
    /// — but never silence either.
    pub breaks: Vec<String>,
}

impl RunState {
    pub fn host(&self, id: &str) -> Option<&HostRun> {
        self.hosts.get(id)
    }

    /// Whether every host reached a state nothing more will happen from.
    pub fn is_finished(&self) -> bool {
        self.ended_at.is_some()
    }
}

/// Read a journal into what it says. Pure, and it is the only thing that
/// decides what an interrupted run knows about itself.
pub fn fold(events: &[JournalEvent]) -> Result<RunState> {
    let mut state = RunState {
        run_id: String::new(),
        plan_id: String::new(),
        started_at: None,
        ended_at: None,
        operator: None,
        hosts: BTreeMap::new(),
        last_seq: 0,
        checks: Vec::new(),
        breaks: Vec::new(),
    };

    for event in events {
        if event.seq <= state.last_seq {
            bail!(
                "this journal goes backwards: entry {} comes after {}. An append-only file \
                 that is not in order is not one this tool wrote.",
                event.seq,
                state.last_seq
            );
        }
        if event.seq > state.last_seq + 1 && state.last_seq > 0 {
            state.breaks.push(format!(
                "the journal jumps from entry {} to entry {}; {} line(s) are missing.",
                state.last_seq,
                event.seq,
                event.seq - state.last_seq - 1
            ));
        }
        state.last_seq = event.seq;

        if state.run_id.is_empty() {
            state.run_id = event.run_id.clone();
            state.plan_id = event.plan_id.clone();
        } else if state.run_id != event.run_id {
            bail!(
                "this journal carries two runs, {} and {}. One run, one journal.",
                state.run_id,
                event.run_id
            );
        }

        match event.event {
            EventKind::RunStart => {
                state.started_at = Some(event.ts);
                if let Ok(payload) =
                    serde_json::from_value::<RunStartPayload>(event.payload.clone())
                {
                    state.operator = Some(payload.operator);
                }
            }
            EventKind::RunEnd => state.ended_at = Some(event.ts),
            EventKind::LockAcquire | EventKind::LockRelease => {
                let host = host_of(event)?;
                let entry = state
                    .hosts
                    .entry(host.clone())
                    .or_insert_with(|| HostRun::new(host));
                entry.lock_held = event.event == EventKind::LockAcquire;
            }
            EventKind::HostState => {
                let host = host_of(event)?;
                let Some(to) = &event.to else {
                    bail!("entry {} is a host.state without a `to`.", event.seq);
                };
                let to = HostState::parse(to)?;
                let entry = state
                    .hosts
                    .entry(host.clone())
                    .or_insert_with(|| HostRun::new(host.clone()));
                if let Some(from) = &event.from {
                    let from = HostState::parse(from)?;
                    if from != entry.state {
                        state.breaks.push(format!(
                            "entry {} says {host} left the state {from} and the journal had it \
                             in {}; a line is missing.",
                            event.seq, entry.state
                        ));
                    }
                }
                entry.state = to;
                let payload: StatePayload =
                    serde_json::from_value(event.payload.clone()).unwrap_or_default();
                let view = SystemView {
                    system: payload.system,
                    generation: payload.generation,
                    booted: payload.booted,
                };
                if !view.is_empty() {
                    // The first one is what it was, the last one is what it
                    // is. Both are needed: a receipt that only says "after"
                    // cannot show what was undone.
                    if entry.before.is_empty() {
                        entry.before = view.clone();
                    }
                    entry.after = view;
                }
            }
            EventKind::ActionBegin | EventKind::ActionIrreversible | EventKind::ActionEnd => {
                let host = host_of(event)?;
                let payload: ActionPayload = serde_json::from_value(event.payload.clone())
                    .map_err(|e| {
                        anyhow::anyhow!(
                            "entry {} is an {:?} whose payload does not name its action: {e}. \
                             It has to carry at least `action` and `kind`.",
                            event.seq,
                            event.event
                        )
                    })?;
                let entry = state
                    .hosts
                    .entry(host.clone())
                    .or_insert_with(|| HostRun::new(host.clone()));
                match event.event {
                    EventKind::ActionBegin => entry.actions.push(ActionRun {
                        seq: payload.action,
                        kind: payload.kind,
                        started: event.ts,
                        ended: None,
                        result: None,
                        evidence: payload.evidence,
                        cmd_refs: payload.cmd_refs,
                    }),
                    EventKind::ActionIrreversible => {
                        entry.open_irreversible = Some(OpenAction {
                            seq: payload.action,
                            kind: payload.kind,
                            started: event.ts,
                            txn: payload.txn.clone(),
                        });
                        if payload.txn.is_some() {
                            entry.txn_id = payload.txn;
                        }
                    }
                    EventKind::ActionEnd => {
                        match entry
                            .actions
                            .iter_mut()
                            .rev()
                            .find(|a| a.seq == payload.action)
                        {
                            Some(run) => {
                                run.ended = Some(event.ts);
                                run.result = payload.result;
                                if !payload.evidence.is_empty() {
                                    run.evidence = payload.evidence;
                                }
                                if !payload.cmd_refs.is_empty() {
                                    run.cmd_refs = payload.cmd_refs;
                                }
                            }
                            None => state.breaks.push(format!(
                                "entry {} ends the step {} on {host} and the journal never \
                                 began it.",
                                event.seq, payload.action
                            )),
                        }
                        if entry
                            .open_irreversible
                            .as_ref()
                            .map(|open| open.seq == payload.action)
                            .unwrap_or(false)
                        {
                            entry.open_irreversible = None;
                        }
                        if payload.credentials.is_some() {
                            entry.credential_versions = payload.credentials;
                        }
                        state.checks.extend(payload.checks);
                    }
                    _ => unreachable!("the three action kinds are the arms above"),
                }
            }
        }
    }
    Ok(state)
}

fn host_of(event: &JournalEvent) -> Result<String> {
    event.host.clone().ok_or_else(|| {
        anyhow::anyhow!(
            "entry {} is a {:?} and names no host.",
            event.seq,
            event.event
        )
    })
}

// ---------------------------------------------------------------------------
// The resume table (V17)
// ---------------------------------------------------------------------------

/// What the TARGET says about the transaction, which is the half of the
/// story the journal cannot have.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxnView {
    /// The target has no record. Either nothing ever began, or somebody
    /// removed it.
    None,
    /// Activated and waiting for a word before the revert timer fires.
    Pending {
        deadline: Option<DateTime<Utc>>,
    },
    Confirmed,
    Reverted,
    /// There is a record and it does not say a coherent thing.
    Inconsistent,
}

impl TxnView {
    /// What an observation of a target says about one transaction id, or —
    /// when the run has no id yet — about whatever is open there.
    ///
    /// A target with more than one record is [`TxnView::Inconsistent`] on
    /// purpose: `meister-activate` allows one open transaction at a time, so
    /// two is a state this tool has no rule for, and guessing which one
    /// matters is how the wrong one gets confirmed.
    pub fn of(observation: &HostObservation, txn_id: Option<&str>) -> TxnView {
        let open: Vec<&crate::observation::Txn> = match txn_id {
            Some(id) => observation
                .open_txns
                .iter()
                .filter(|t| t.id == id)
                .collect(),
            None => observation.open_txns.iter().collect(),
        };
        match open.as_slice() {
            [] => TxnView::None,
            [one] => match one.state {
                TxnState::Staged => TxnView::None,
                TxnState::Pending => TxnView::Pending {
                    deadline: one.deadline,
                },
                TxnState::Confirmed => TxnView::Confirmed,
                TxnState::Reverted => TxnView::Reverted,
                TxnState::Inconsistent => TxnView::Inconsistent,
            },
            _ => TxnView::Inconsistent,
        }
    }
}

/// What a resume does to one host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Nothing left this workstation for this host. Begin it again.
    StartOver,
    /// The closure is there and the running system was not touched. Check
    /// the stage against the release and carry on from it.
    ResumeFromStage,
    /// It activated and the target is still waiting for a word: verify, then
    /// confirm — or say nothing and let it revert.
    VerifyAndConfirm,
    /// It activated and somebody already confirmed. Only the verification is
    /// left.
    VerifyOnly,
    /// It went back. The forward attempt stays failed; this is not a
    /// success that happened to take a detour.
    RolledBack,
    /// A person has to look. Nothing is reissued, nothing is repeated,
    /// nothing is activated.
    RecoveryRequired(String),
    /// There is nothing left to do here.
    Done,
}

/// The V17 table.
///
/// Read it as three questions in this order: did anything irreversible
/// begin; if not, how far did the preparation get; if it did, what does the
/// target say. The one rule the table exists to enforce is in the second and
/// third arm: an irreversible step with no end in the journal is decided by
/// the TARGET and never by repeating it.
pub fn next_step(host: &HostRun, target: &TxnView) -> Step {
    let began = host.open_irreversible.is_some() || host.state.past_the_point_of_no_return();

    if !began {
        return match target {
            // Nothing began here and the target has nothing. Whatever was
            // done was preparation, and preparation is repeatable.
            TxnView::None => match host.state {
                HostState::Staged | HostState::MaintenanceReady => Step::ResumeFromStage,
                HostState::Unchanged | HostState::Committed => Step::Done,
                _ => Step::StartOver,
            },
            // The local journal says nothing was activated on this host and
            // the target is carrying a transaction. Either this journal lost
            // its lines or somebody else was here. Nothing is reissued and
            // nothing is repeated.
            _ => Step::RecoveryRequired(format!(
                "the journal of this run says nothing was activated on {} and the target has a \
                 transaction. Look at `meister-activate txn list` on the host and decide there; \
                 this tool will not activate on top of it.",
                host.id
            )),
        };
    }

    match target {
        TxnView::Confirmed => {
            if host.state == HostState::Committed {
                Step::Done
            } else {
                Step::VerifyOnly
            }
        }
        TxnView::Pending { .. } => Step::VerifyAndConfirm,
        TxnView::Reverted => Step::RolledBack,
        TxnView::None => Step::RecoveryRequired(format!(
            "an irreversible step began on {} and the target has no transaction record for it. \
             The journal cannot say what happened after the line it managed to write, and \
             repeating an activation blind is how a machine ends up half-switched.",
            host.id
        )),
        TxnView::Inconsistent => Step::RecoveryRequired(format!(
            "the transaction record on {} does not say a coherent thing. Read it with \
             `meister-activate txn show` and decide there.",
            host.id
        )),
    }
}

// ---------------------------------------------------------------------------
// The receipt
// ---------------------------------------------------------------------------

/// Where the journal for this run is, and what it hashed to when the receipt
/// was written. Handed in rather than computed: a fold cannot know what a
/// file on disk hashes to, and a receipt that names no journal is a summary
/// rather than evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalRef {
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostReceipt {
    pub outcome: HostOutcome,
    /// The state it ended in, which carries more than the outcome does.
    pub state: HostState,
    pub before: SystemView,
    pub after: SystemView,
    pub actions: Vec<ActionRun>,
    pub credential_versions: Option<CredentialVersions>,
    pub txn_id: Option<String>,
}

/// `receipt.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeploymentReceipt {
    pub schema: String,
    pub run_id: String,
    pub plan_id: String,
    pub release_id: String,
    pub started_at: Option<DateTime<Utc>>,
    pub ended_at: Option<DateTime<Utc>>,
    pub operator: Option<Operator>,
    pub outcome: Outcome,
    /// Every host of the plan's frozen selection — including the ones
    /// nothing happened to.
    pub hosts: BTreeMap<String, HostReceipt>,
    /// The hosts of the selection the run never got to. Named, because "the
    /// rollout stopped" without a list is not something anybody can act on.
    pub untouched: Vec<String>,
    pub checks: Vec<CheckResult>,
    /// What the journal does not add up to, carried into the receipt rather
    /// than left in a log.
    pub breaks: Vec<String>,
    pub journal_path: String,
    pub journal_sha256: String,
}

impl DeploymentReceipt {
    pub fn from_json(text: &str, origin: &str) -> Result<DeploymentReceipt> {
        crate::manifest::parse_checked(text, origin, RECEIPT_SCHEMA)
    }

    pub fn to_json(&self) -> Result<Vec<u8>> {
        let mut bytes = serde_json::to_vec_pretty(self)
            .map_err(|e| anyhow::anyhow!("writing the receipt as json failed: {e}"))?;
        bytes.push(b'\n');
        Ok(bytes)
    }
}

/// Fold a run into the thing somebody attaches to a ticket.
///
/// Pure. Every host of the plan's frozen selection appears, whether the run
/// reached it or not: a receipt that lists only what happened cannot be
/// checked against the plan it claims to be about.
pub fn receipt(
    plan: &DeploymentPlan,
    state: &RunState,
    journal: &JournalRef,
    now: DateTime<Utc>,
) -> DeploymentReceipt {
    let mut hosts = BTreeMap::new();
    let mut untouched = Vec::new();

    for id in &plan.selection.targets {
        let run = state.hosts.get(id);
        let planned = &plan.hosts[id];
        let host_state = match run {
            Some(run) => run.state,
            // The journal never mentioned it. A host the plan already
            // refused was refused, whatever the run did afterwards.
            None if planned.verdict.blocks() => HostState::Blocked,
            None if planned.verdict == HostVerdict::Unchanged => HostState::Planned,
            None => HostState::Planned,
        };
        if host_state == HostState::Planned {
            untouched.push(id.clone());
        }
        hosts.insert(
            id.clone(),
            HostReceipt {
                outcome: HostOutcome::of(host_state),
                state: host_state,
                before: run.map(|r| r.before.clone()).unwrap_or_default(),
                after: run.map(|r| r.after.clone()).unwrap_or_default(),
                actions: run.map(|r| r.actions.clone()).unwrap_or_default(),
                credential_versions: run.and_then(|r| r.credential_versions.clone()),
                txn_id: run.and_then(|r| r.txn_id.clone()),
            },
        );
    }

    let outcomes: Vec<HostOutcome> = hosts.values().map(|h| h.outcome).collect();
    let any_failure = outcomes.iter().any(|o| o.is_failure());
    let any_forward = outcomes.iter().any(|o| o.is_forward());
    let all_forward = !outcomes.is_empty() && outcomes.iter().all(|o| o.is_forward());
    let outcome = if all_forward {
        Outcome::Success
    } else if any_failure && any_forward {
        Outcome::Partial
    } else if any_failure {
        // A rollback that worked is still a rollout that did not: the
        // forward attempt failed, and saying "success" because the machine
        // came back is how a broken release ships.
        Outcome::Failed
    } else if any_forward {
        Outcome::Partial
    } else {
        Outcome::Aborted
    };

    DeploymentReceipt {
        schema: RECEIPT_SCHEMA.to_string(),
        run_id: state.run_id.clone(),
        plan_id: plan.plan_id.clone(),
        release_id: plan.release_id.clone(),
        started_at: state.started_at,
        ended_at: state.ended_at.or(Some(now)),
        operator: state.operator.clone(),
        outcome,
        hosts,
        untouched,
        checks: state.checks.clone(),
        breaks: state.breaks.clone(),
        journal_path: journal.path.clone(),
        journal_sha256: journal.sha256.clone(),
    }
}

/// Which hosts of a plan still have something to do, for a resume. Keyed the
/// way `apply` walks them: in the plan's own wave order.
pub fn unfinished(plan: &DeploymentPlan, state: &RunState) -> BTreeSet<String> {
    plan.selection
        .targets
        .iter()
        .filter(|id| {
            let done = state
                .hosts
                .get(*id)
                .map(|r| matches!(r.state, HostState::Committed | HostState::Unchanged))
                .unwrap_or(false);
            !done
        })
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{
        at, observed, onebox_enrolled, plan_policy, release_of, with_new_systems,
    };
    use crate::observation::Txn;
    use crate::plan::{DeploymentPlan, PlanKind, plan};

    const RUN: &str = "0192f0c0-7e4e-7000-8000-000000000001";

    fn a_plan() -> DeploymentPlan {
        let base = onebox_enrolled();
        let running = release_of(base.clone());
        let observation = observed(&running, at("2026-09-21T11:59:00Z"));
        let release = with_new_systems(base, &["n1", "n2"], false);
        plan(
            &release,
            "host=n1,host=n2",
            &observation,
            None,
            &plan_policy(PlanKind::Upgrade),
            at("2026-09-21T12:00:00Z"),
        )
        .expect("the fixture plans")
    }

    /// A journal builder: every line gets the next sequence number and a
    /// timestamp a minute after the last.
    struct Log {
        plan_id: String,
        events: Vec<JournalEvent>,
    }

    impl Log {
        fn new(plan: &DeploymentPlan) -> Log {
            let mut log = Log {
                plan_id: plan.plan_id.clone(),
                events: Vec::new(),
            };
            log.push(EventKind::RunStart, None, |e| {
                e.payload(serde_json::json!({
                    "operator": {"user": "silas", "workstation": "manacor"}
                }))
            });
            log
        }

        fn push(
            &mut self,
            kind: EventKind,
            host: Option<&str>,
            build: impl Fn(JournalEvent) -> JournalEvent,
        ) -> &mut Log {
            let seq = self.events.len() as u64 + 1;
            let ts = at("2026-09-21T12:00:00Z") + chrono::TimeDelta::seconds(seq as i64 * 60);
            let mut event = JournalEvent::new(seq, ts, RUN, &self.plan_id, kind);
            if let Some(host) = host {
                event = event.host(host);
            }
            self.events.push(build(event));
            self
        }

        fn state(&mut self, host: &str, from: HostState, to: HostState) -> &mut Log {
            self.push(EventKind::HostState, Some(host), |e| e.transition(from, to))
        }

        fn state_with(
            &mut self,
            host: &str,
            from: HostState,
            to: HostState,
            payload: serde_json::Value,
        ) -> &mut Log {
            self.push(EventKind::HostState, Some(host), move |e| {
                e.transition(from, to).payload(payload.clone())
            })
        }

        fn action(&mut self, host: &str, kind: EventKind, payload: serde_json::Value) -> &mut Log {
            self.push(kind, Some(host), move |e| e.payload(payload.clone()))
        }

        fn folded(&self) -> RunState {
            fold(&self.events).expect("this journal folds")
        }
    }

    fn begin(seq: u32, kind: &str) -> serde_json::Value {
        serde_json::json!({"action": seq, "kind": kind})
    }

    fn end(seq: u32, kind: &str, result: &str) -> serde_json::Value {
        serde_json::json!({"action": seq, "kind": kind, "result": result})
    }

    #[test]
    fn a_journal_line_reads_back_from_what_it_writes() {
        let plan = a_plan();
        let event = JournalEvent::new(
            1,
            at("2026-09-21T12:00:00Z"),
            RUN,
            &plan.plan_id,
            EventKind::HostState,
        )
        .host("n1")
        .transition(HostState::Planned, HostState::Preflight);
        let line = event.to_line().unwrap();
        assert!(line.contains(r#""event":"host.state""#), "{line}");
        assert!(line.contains(r#""to":"preflight""#), "{line}");
        let back = parse_journal(&format!("{line}\n\n"), "the round trip").unwrap();
        assert_eq!(back, vec![event]);
    }

    #[test]
    fn a_journal_that_goes_backwards_is_not_one_this_tool_wrote() {
        let plan = a_plan();
        let one = JournalEvent::new(
            2,
            at("2026-09-21T12:00:00Z"),
            RUN,
            &plan.plan_id,
            EventKind::RunStart,
        );
        let two = JournalEvent::new(
            1,
            at("2026-09-21T12:01:00Z"),
            RUN,
            &plan.plan_id,
            EventKind::RunEnd,
        );
        let err = fold(&[one, two]).unwrap_err().to_string();
        assert!(err.contains("goes backwards"), "{err}");
    }

    #[test]
    fn a_gap_in_the_journal_is_recorded_and_not_swallowed() {
        let plan = a_plan();
        let one = JournalEvent::new(
            1,
            at("2026-09-21T12:00:00Z"),
            RUN,
            &plan.plan_id,
            EventKind::RunStart,
        );
        let far = JournalEvent::new(
            5,
            at("2026-09-21T12:05:00Z"),
            RUN,
            &plan.plan_id,
            EventKind::RunEnd,
        );
        let state = fold(&[one, far]).unwrap();
        assert_eq!(state.breaks.len(), 1);
        assert!(
            state.breaks[0].contains("3 line(s) are missing"),
            "{:?}",
            state.breaks
        );
    }

    #[test]
    fn two_runs_in_one_journal_are_refused() {
        let plan = a_plan();
        let mine = JournalEvent::new(
            1,
            at("2026-09-21T12:00:00Z"),
            RUN,
            &plan.plan_id,
            EventKind::RunStart,
        );
        let theirs = JournalEvent::new(
            2,
            at("2026-09-21T12:01:00Z"),
            "another-run",
            &plan.plan_id,
            EventKind::RunEnd,
        );
        let err = fold(&[mine, theirs]).unwrap_err().to_string();
        assert!(err.contains("two runs"), "{err}");
    }

    #[test]
    fn a_transition_out_of_a_state_the_host_was_not_in_is_a_break() {
        let plan = a_plan();
        let mut log = Log::new(&plan);
        log.state("n1", HostState::Staged, HostState::Activating);
        let state = log.folded();
        assert_eq!(state.hosts["n1"].state, HostState::Activating);
        assert!(
            state.breaks[0].contains("left the state staged"),
            "{:?}",
            state.breaks
        );
    }

    #[test]
    fn the_fold_keeps_the_first_system_and_the_last() {
        let plan = a_plan();
        let mut log = Log::new(&plan);
        log.state_with(
            "n1",
            HostState::Planned,
            HostState::Preflight,
            serde_json::json!({"system": "/nix/store/before", "generation": 41, "booted": "/nix/store/before"}),
        );
        log.state_with(
            "n1",
            HostState::Preflight,
            HostState::Committed,
            serde_json::json!({"system": "/nix/store/after", "generation": 42, "booted": "/nix/store/before"}),
        );
        let state = log.folded();
        let host = &state.hosts["n1"];
        assert_eq!(host.before.system.as_deref(), Some("/nix/store/before"));
        assert_eq!(host.before.generation, Some(41));
        assert_eq!(host.after.system.as_deref(), Some("/nix/store/after"));
    }

    #[test]
    fn an_action_that_began_and_ended_is_one_entry_with_both_times() {
        let plan = a_plan();
        let mut log = Log::new(&plan);
        log.action("n1", EventKind::ActionBegin, begin(3, "stage"));
        log.action(
            "n1",
            EventKind::ActionEnd,
            serde_json::json!({
                "action": 3, "kind": "stage", "result": "ok",
                "evidence": ["nix path-info agreed"], "cmd_refs": ["cmd-1"]
            }),
        );
        let state = log.folded();
        let actions = &state.hosts["n1"].actions;
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].kind, ActionKind::Stage);
        assert_eq!(actions[0].result, Some(ActionResult::Ok));
        assert!(actions[0].ended.is_some());
        assert_eq!(actions[0].evidence, ["nix path-info agreed"]);
    }

    #[test]
    fn an_action_payload_that_names_no_action_is_an_error_with_the_line() {
        let plan = a_plan();
        let event = JournalEvent::new(
            1,
            at("2026-09-21T12:00:00Z"),
            RUN,
            &plan.plan_id,
            EventKind::ActionBegin,
        )
        .host("n1")
        .payload(serde_json::json!({"whatever": true}));
        let err = fold(&[event]).unwrap_err().to_string();
        assert!(err.contains("entry 1"), "{err}");
        assert!(err.contains("`action` and `kind`"), "{err}");
    }

    #[test]
    fn an_irreversible_step_stays_open_until_its_end_is_written() {
        let plan = a_plan();
        let mut log = Log::new(&plan);
        log.action("n1", EventKind::ActionBegin, begin(6, "activate"));
        log.action(
            "n1",
            EventKind::ActionIrreversible,
            serde_json::json!({"action": 6, "kind": "activate", "txn": "txn-1"}),
        );
        let mid = log.folded();
        assert_eq!(mid.hosts["n1"].open_irreversible.as_ref().unwrap().seq, 6);
        assert_eq!(mid.hosts["n1"].txn_id.as_deref(), Some("txn-1"));

        log.action("n1", EventKind::ActionEnd, end(6, "activate", "ok"));
        let after = log.folded();
        assert!(after.hosts["n1"].open_irreversible.is_none());
        assert_eq!(after.hosts["n1"].txn_id.as_deref(), Some("txn-1"));
    }

    // --- the V17 table -------------------------------------------------

    fn host_in(state: HostState) -> HostRun {
        let mut run = HostRun::new("n1");
        run.state = state;
        run
    }

    fn mid_activation() -> HostRun {
        let mut run = host_in(HostState::Activating);
        run.open_irreversible = Some(OpenAction {
            seq: 6,
            kind: ActionKind::Activate,
            started: at("2026-09-21T12:06:00Z"),
            txn: Some("txn-1".to_string()),
        });
        run.txn_id = Some("txn-1".to_string());
        run
    }

    #[test]
    fn interrupted_before_anything_was_transferred_it_begins_again() {
        for state in [HostState::Planned, HostState::Preflight] {
            assert_eq!(
                next_step(&host_in(state), &TxnView::None),
                Step::StartOver,
                "{state}"
            );
        }
    }

    #[test]
    fn interrupted_after_the_transfer_and_before_the_activation_it_carries_on() {
        for state in [HostState::Staged, HostState::MaintenanceReady] {
            assert_eq!(
                next_step(&host_in(state), &TxnView::None),
                Step::ResumeFromStage,
                "{state}"
            );
        }
    }

    #[test]
    fn an_irreversible_step_without_an_end_is_decided_by_the_target() {
        // Confirmed: it stuck. Only the verification is left.
        assert_eq!(
            next_step(&mid_activation(), &TxnView::Confirmed),
            Step::VerifyOnly
        );
        // Pending: it is activated and the timer is running.
        assert_eq!(
            next_step(
                &mid_activation(),
                &TxnView::Pending {
                    deadline: Some(at("2026-09-21T12:16:00Z"))
                }
            ),
            Step::VerifyAndConfirm
        );
        // Reverted: the forward attempt stays failed.
        assert_eq!(
            next_step(&mid_activation(), &TxnView::Reverted),
            Step::RolledBack
        );
    }

    #[test]
    fn an_irreversible_step_the_target_knows_nothing_about_needs_a_person() {
        let step = next_step(&mid_activation(), &TxnView::None);
        match step {
            Step::RecoveryRequired(why) => {
                assert!(why.contains("no transaction record"), "{why}");
                assert!(why.contains("half-switched"), "{why}");
            }
            other => panic!("{other:?} — an activation must never be repeated blind"),
        }
        let step = next_step(&mid_activation(), &TxnView::Inconsistent);
        assert!(matches!(step, Step::RecoveryRequired(_)));
    }

    #[test]
    fn an_empty_journal_and_a_target_with_a_transaction_needs_a_person() {
        // The half of V17 that is about a lost journal rather than a lost
        // host. Nothing is reissued.
        let step = next_step(&HostRun::new("n1"), &TxnView::Pending { deadline: None });
        match step {
            Step::RecoveryRequired(why) => {
                assert!(why.contains("says nothing was activated"), "{why}");
                assert!(why.contains("will not activate on top of it"), "{why}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn after_the_confirmation_there_is_nothing_left_to_do() {
        assert_eq!(
            next_step(&host_in(HostState::Committed), &TxnView::Confirmed),
            Step::Done
        );
        assert_eq!(
            next_step(&host_in(HostState::Unchanged), &TxnView::None),
            Step::Done
        );
    }

    #[test]
    fn what_the_target_says_comes_from_its_own_transaction_records() {
        let mut obs = crate::observation::HostObservation::empty();
        assert_eq!(TxnView::of(&obs, None), TxnView::None);

        obs.open_txns = vec![Txn {
            id: "txn-1".to_string(),
            state: TxnState::Pending,
            target_system: None,
            deadline: Some(at("2026-09-21T12:16:00Z")),
            run_id: None,
        }];
        assert_eq!(
            TxnView::of(&obs, Some("txn-1")),
            TxnView::Pending {
                deadline: Some(at("2026-09-21T12:16:00Z"))
            }
        );
        // A record for another transaction is not this run's answer.
        assert_eq!(TxnView::of(&obs, Some("txn-9")), TxnView::None);
        // A staged transaction has not activated anything.
        obs.open_txns[0].state = TxnState::Staged;
        assert_eq!(TxnView::of(&obs, None), TxnView::None);
        // Two records is a state this tool has no rule for.
        obs.open_txns.push(Txn {
            id: "txn-2".to_string(),
            state: TxnState::Confirmed,
            target_system: None,
            deadline: None,
            run_id: None,
        });
        assert_eq!(TxnView::of(&obs, None), TxnView::Inconsistent);
    }

    // --- the receipt ---------------------------------------------------

    fn journal_ref() -> JournalRef {
        JournalRef {
            path: ".meister-deploy/runs/0192/journal.jsonl".to_string(),
            sha256: "0".repeat(64),
        }
    }

    #[test]
    fn a_run_where_everything_went_forward_is_a_success() {
        let plan = a_plan();
        let mut log = Log::new(&plan);
        for host in ["n1", "n2"] {
            log.state(host, HostState::Planned, HostState::Committed);
        }
        log.push(EventKind::RunEnd, None, |e| e);
        let out = receipt(
            &plan,
            &log.folded(),
            &journal_ref(),
            at("2026-09-21T13:00:00Z"),
        );
        assert_eq!(out.outcome, Outcome::Success);
        assert_eq!(out.hosts["n1"].outcome, HostOutcome::Success);
        assert!(out.untouched.is_empty());
        assert_eq!(out.operator.as_ref().unwrap().user, "silas");
        assert_eq!(out.journal_sha256, "0".repeat(64));
        assert_eq!(out.plan_id, plan.plan_id);
    }

    #[test]
    fn a_verified_rollback_is_a_failure_and_never_a_success() {
        let plan = a_plan();
        let mut log = Log::new(&plan);
        log.state("n1", HostState::Planned, HostState::RolledBack);
        log.state("n2", HostState::Planned, HostState::RolledBack);
        log.push(EventKind::RunEnd, None, |e| e);
        let out = receipt(
            &plan,
            &log.folded(),
            &journal_ref(),
            at("2026-09-21T13:00:00Z"),
        );
        assert_eq!(out.hosts["n1"].outcome, HostOutcome::RolledBack);
        assert_eq!(
            out.outcome,
            Outcome::Failed,
            "the machine came back and the rollout did not happen"
        );
        assert_ne!(out.outcome, Outcome::Success);
    }

    #[test]
    fn one_host_forward_and_one_back_is_partial() {
        let plan = a_plan();
        let mut log = Log::new(&plan);
        log.state("n1", HostState::Planned, HostState::Committed);
        log.state("n2", HostState::Planned, HostState::RolledBack);
        log.push(EventKind::RunEnd, None, |e| e);
        let out = receipt(
            &plan,
            &log.folded(),
            &journal_ref(),
            at("2026-09-21T13:00:00Z"),
        );
        assert_eq!(out.outcome, Outcome::Partial);
    }

    #[test]
    fn a_run_that_never_got_to_a_host_says_which_one() {
        let plan = a_plan();
        let mut log = Log::new(&plan);
        log.state("n1", HostState::Planned, HostState::Committed);
        let out = receipt(
            &plan,
            &log.folded(),
            &journal_ref(),
            at("2026-09-21T13:00:00Z"),
        );
        assert_eq!(out.untouched, ["n2"]);
        assert_eq!(out.hosts["n2"].outcome, HostOutcome::Unreached);
        assert_eq!(out.outcome, Outcome::Partial);
        // and the run has an end even when the journal has none
        assert_eq!(out.ended_at, Some(at("2026-09-21T13:00:00Z")));
    }

    #[test]
    fn a_run_that_did_nothing_at_all_is_aborted_and_not_a_success() {
        let plan = a_plan();
        let log = Log::new(&plan);
        let out = receipt(
            &plan,
            &log.folded(),
            &journal_ref(),
            at("2026-09-21T13:00:00Z"),
        );
        assert_eq!(out.outcome, Outcome::Aborted);
        assert_eq!(out.untouched, ["n1", "n2"]);
    }

    #[test]
    fn a_host_in_the_middle_of_an_activation_is_unknown_and_not_a_failure() {
        let plan = a_plan();
        let mut log = Log::new(&plan);
        log.state("n1", HostState::Planned, HostState::Activating);
        log.state("n2", HostState::Planned, HostState::Committed);
        let out = receipt(
            &plan,
            &log.folded(),
            &journal_ref(),
            at("2026-09-21T13:00:00Z"),
        );
        assert_eq!(out.hosts["n1"].outcome, HostOutcome::Unknown);
        assert_eq!(out.outcome, Outcome::Partial);
    }

    #[test]
    fn the_receipt_carries_the_credentials_and_the_transaction() {
        let plan = a_plan();
        let mut log = Log::new(&plan);
        log.action("n1", EventKind::ActionBegin, begin(6, "activate"));
        log.action(
            "n1",
            EventKind::ActionIrreversible,
            serde_json::json!({"action": 6, "kind": "activate", "txn": "txn-1"}),
        );
        log.action(
            "n1",
            EventKind::ActionEnd,
            serde_json::json!({
                "action": 6, "kind": "activate", "result": "ok",
                "credentials": {
                    "identity_serial": "04A7", "ca_fingerprint": "SHA256:ca", "crl_number": "7"
                }
            }),
        );
        log.state("n1", HostState::Planned, HostState::Committed);
        let out = receipt(
            &plan,
            &log.folded(),
            &journal_ref(),
            at("2026-09-21T13:00:00Z"),
        );
        let host = &out.hosts["n1"];
        assert_eq!(host.txn_id.as_deref(), Some("txn-1"));
        assert_eq!(
            host.credential_versions
                .as_ref()
                .unwrap()
                .identity_serial
                .as_deref(),
            Some("04A7")
        );
    }

    #[test]
    fn a_check_recorded_in_the_journal_reaches_the_receipt() {
        let plan = a_plan();
        let mut log = Log::new(&plan);
        log.action("n1", EventKind::ActionBegin, begin(7, "verify"));
        log.action(
            "n1",
            EventKind::ActionEnd,
            serde_json::json!({
                "action": 7, "kind": "verify", "result": "ok",
                "checks": [{
                    "id": "units", "subject": {"host": "n1", "resource": null},
                    "required": true, "status": "pass", "expected": "active",
                    "observed": "active", "reason": "the agent unit is running",
                    "duration_ms": 12, "evidence": [], "release_id": null, "config_id": null
                }]
            }),
        );
        let out = receipt(
            &plan,
            &log.folded(),
            &journal_ref(),
            at("2026-09-21T13:00:00Z"),
        );
        assert_eq!(out.checks.len(), 1);
        assert_eq!(out.checks[0].id, "units");
    }

    #[test]
    fn a_receipt_reads_back_from_its_own_json() {
        let plan = a_plan();
        let mut log = Log::new(&plan);
        log.state("n1", HostState::Planned, HostState::Committed);
        log.push(EventKind::RunEnd, None, |e| e);
        let out = receipt(
            &plan,
            &log.folded(),
            &journal_ref(),
            at("2026-09-21T13:00:00Z"),
        );
        let text = String::from_utf8(out.to_json().unwrap()).unwrap();
        assert_eq!(
            DeploymentReceipt::from_json(&text, "the round trip").unwrap(),
            out
        );
    }

    #[test]
    fn what_is_left_to_do_is_what_did_not_finish() {
        let plan = a_plan();
        let mut log = Log::new(&plan);
        log.state("n1", HostState::Planned, HostState::Committed);
        log.state("n2", HostState::Planned, HostState::Staged);
        let left = unfinished(&plan, &log.folded());
        assert_eq!(left.into_iter().collect::<Vec<_>>(), ["n2"]);
    }
}

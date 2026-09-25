// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! VM intent, placement, observed state and runtime access information.

use super::*;

/// The agent's Desired vocabulary, 1:1. Absent happens through DELETE.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum RunStrategy {
    #[default]
    Running,
    Stopped,
    Paused,
}

impl RunStrategy {
    /// Every variant, in declaration order. The tables that enumerate the
    /// controller's decisions walk this instead of each keeping a list of its
    /// own — one list, and `the_variant_lists_name_every_variant` is what
    /// makes adding a variant a compile error rather than a silent gap.
    pub const ALL: [RunStrategy; 3] = [
        RunStrategy::Running,
        RunStrategy::Stopped,
        RunStrategy::Paused,
    ];

    /// The spelling on the wire and in a sentence — the same word serde
    /// writes, so a refusal quoting it names the value a client sent.
    pub fn as_str(self) -> &'static str {
        match self {
            RunStrategy::Running => "Running",
            RunStrategy::Stopped => "Stopped",
            RunStrategy::Paused => "Paused",
        }
    }
}

/// How far a drain may go to move this VM off its machine.
///
/// Two words and deliberately not three. There is no `live` variant, because
/// live migration is not something an owner OPTS INTO — it is something the
/// stack does when it can (no passthrough device, no node-local disk) and
/// cannot promise otherwise. What an owner decides is whether a reboot is an
/// acceptable price, and that is the whole of the question this answers.
///
/// The thesis sentence behind it: moving a GPU VM costs a reboot, and the
/// stack says so instead of pretending otherwise.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Evacuation {
    /// Leave it where it is. A drain lists it and moves on.
    ///
    /// The default, and the only safe one: a VM whose owner never said
    /// anything must not be rebooted by an operator's drain.
    #[default]
    Never,
    /// Stop it, place it again, start it — one operation, and the guest sees
    /// a reboot.
    ///
    /// The GPU case: a VM with a device can never move live, and the choice
    /// is between a reboot and staying put. It is also the answer for a VM
    /// that could move live but whose owner would rather not wait for a
    /// migration to converge.
    Restart,
}

impl Evacuation {
    pub const ALL: [Evacuation; 2] = [Evacuation::Never, Evacuation::Restart];

    pub fn as_str(self) -> &'static str {
        match self {
            Evacuation::Never => "never",
            Evacuation::Restart => "restart",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|e| e.as_str() == s)
    }

    /// The default, so that it is skipped on the way out and every VM written
    /// before this field looks exactly as it did.
    pub fn is_never(&self) -> bool {
        matches!(self, Evacuation::Never)
    }
}

reasons! {
    /// Bounded reason categories for API status and metrics.
    ///
    /// Controller decisions and node reports share this list; node reason names
    /// must match `proto::reasons::VM`. Messages retain detailed context such as
    /// candidate counts and missing capabilities.
    VmReason [18] {
        /// Nobody recorded one.
        ///
        /// Not a failure of this enum but the honest value in two cases: a
        /// phase stored before struktur 4, and a writer that genuinely has
        /// nothing categorical to say. The next pass replaces it — which is
        /// decision 6 of the brief, and the reason there is no migration
        /// code anywhere in this change.
        #[default]
        Unrecorded => "Unrecorded",
        /// Nobody has looked yet, or nobody has been told yet: the moment
        /// between the create and the first scheduler pass, and the moment
        /// between the binding and the create going out.
        ///
        /// Not `Unplaced`, which is the scheduler having LOOKED and found
        /// nowhere. Spelled as the image's, the pool's, the copy's, the
        /// volume's and the router's are, so that "nobody has said anything
        /// yet" is one word across this crate.
        AwaitingNode => "AwaitingNode",
        /// The scheduler found nowhere to put it: nothing is a candidate,
        /// nothing has room, or nothing carries what the VM asks for. A WALL
        /// — somebody has to change a machine or the VM. Which of the ten
        /// `PendingReason` cases it was stays in the sentence.
        Unplaced => "Unplaced",
        /// Something this VM needs is being made and is not there yet: a
        /// volume, a secret. A WAIT, and its own word for that reason —
        /// `Unplaced` sends somebody to the fleet, this one sends them
        /// nowhere at all.
        NotReady => "NotReady",
        /// A disk this VM refers to exists and is somebody else's: the claim
        /// on it names another guest, or a node still reports it open.
        ///
        /// Not `NotReady`, and the difference is who has to act. `NotReady`
        /// is a wait on this control plane — the bytes are being made and
        /// will arrive. This is a wait on a PERSON: nothing here will ever
        /// take a disk off the guest holding it. It is also the phase that
        /// makes D4 safe to read: the claim now falls when the last holder
        /// has gone AND no node reports the bytes open, so the window in
        /// between is a VM that says who has its disk instead of one that
        /// says "not ready" for ever.
        VolumeHeld => "VolumeHeld",
        /// The tier below let the binding go: the VM is nowhere, and it is
        /// waiting to be placed again. `session::ingest`, both tiers.
        Unbound => "Unbound",
        /// The command has gone out and nobody has reported on it yet. The
        /// one reason that is a GUESS about the future, and the reconciler
        /// writes it only over a VM nobody has reported on at all.
        Dispatched => "Dispatched",
        /// A machine or a cluster refused to serve it — `CannotServe` at the
        /// cluster, a refused create at the cloud. Structural: the same
        /// answer comes back next pass, which is why it is remembered.
        Refused => "Refused",
        /// Nobody has heard from the machine holding it for longer than the
        /// heartbeat allows — a node at the cluster, a cluster at the cloud.
        /// ONE word for both, and the sentence says which ("node X last
        /// reported …"). The brief asks for two; there are eight slots and
        /// this is the pair whose difference is already in the sentence.
        Silent => "Silent",

        // ------------------------------------------------------------------
        // The node's own words from here down: `proto::reasons::VM`, parsed
        // off `VmStatusReport.reason` and written onto the object unchanged.
        // A cluster relaying a VM to the cloud passes the word it was given
        // on, so the same eight arrive at both tiers and mean the same thing.
        // ------------------------------------------------------------------

        /// `Provisioning`: a pass is building this guest and the last attempt
        /// did not fail. The ordinary road up to `Running`.
        Working => "Working",
        /// `Provisioning`: the last attempt DID fail and the retry schedule
        /// is waiting. The sentence is that attempt's error — the half of
        /// this state nobody could see, because a count says a VM is not
        /// coming up and never says what stopped it.
        Backoff => "Backoff",
        /// `Provisioning`: the node is a live migration's destination and the
        /// guest has not arrived yet.
        AwaitingGuest => "AwaitingGuest",
        /// `Provisioning`: the node WAS a live migration's source and the
        /// guest is on the other machine now.
        GuestLeft => "GuestLeft",
        /// `Failed`: a reception did not finish and the node is giving back
        /// the VMM, the disks and the taps it made. The guest is still
        /// running where it was, which is the invariant behind the word.
        ReceiveFailed => "ReceiveFailed",
        /// `Failed`: the VMM is gone or does not answer its socket, and the
        /// passes that tried to rebuild it keep failing. The requeue curve is
        /// what acts on this.
        VmmGone => "VmmGone",
        /// `Quarantined`: a storage backend died while the VMM went on
        /// running. No pass may repair it by itself — a rebuild would be this
        /// tier deciding what happened to a guest that is still executing.
        BackendGone => "BackendGone",
        /// `Quarantined`: the guest did not come back from a pause however
        /// often it was resumed.
        ResumeIneffective => "ResumeIneffective",
        /// `Provisioning`: the node was told the VM is to be `Absent` and has
        /// not finished taking it apart. Its VMM may still be running and its
        /// disks may still be open.
        ///
        /// The one word here that says "do NOT act yet". A node used to stop
        /// naming such a VM the moment the intent was written, and absence
        /// from a node's report is what `session::ingest::forget_unbound`
        /// reads as "that node has let go" — so a VM could be placed
        /// elsewhere while the first node's VMM still held its volumes.
        /// Astra finding S12, 2026-09-23.
        Stopping => "Stopping",
    }
}

phases! {
    /// What this control plane says a VM is doing.
    VmPhase / VmPhaseKind / VmReason / VmPhaseWire / VmReported [8] {
        Pending { reason, message, since } => "Pending",
        Provisioning { reason, message, since } => "Provisioning",
        Running { message, since } => "Running",
        Stopped { message, since } => "Stopped",
        Paused { message, since } => "Paused",
        Failed { reason, message, since } => "Failed",
        Quarantined { reason, message, since } => "Quarantined",
        /// The holder has stopped reporting; the guest state is unknown.
        ///
        /// Silence is not proof that a guest stopped. This phase does not enter
        /// failure requeue or become Failed after a deadline. A fresh observation
        /// resolves it; deadlines only produce events and metrics. Cluster reports
        /// may relay Unknown to the cloud.
        Unknown { reason, message, since } => "Unknown",
    }
}

impl VmPhaseKind {
    /// The three phases that have come to rest. Everything else means a pass
    /// is in flight (Pending, Provisioning), the agent's own backoff is
    /// working (Failed), the VM is deliberately nobody's to touch
    /// (Quarantined), or nobody knows (Unknown) — and nothing automatic
    /// argues with any of those.
    ///
    /// `Unknown` is emphatically not stable, and it is the one that would be
    /// tempting: it looks settled, and it is the opposite. A lifecycle
    /// command derived from it would be a Stop or a Start sent at a guest
    /// nobody has looked at, down a session that does not exist.
    pub fn is_stable(self) -> bool {
        matches!(
            self,
            VmPhaseKind::Running | VmPhaseKind::Stopped | VmPhaseKind::Paused
        )
    }

    /// Nothing in this stack is going to move this phase on its own, so it
    /// cannot be late for anything (see `crate::stuck`).
    ///
    /// The three resting states, and `Quarantined` beside them: a quarantined
    /// VM is deliberately nobody's to touch, which is exactly "nothing will
    /// move it". `Failed` is NOT here — the requeue curve acts on it, so it
    /// is a wait rather than an end, and it gets no second deadline over the
    /// top of a backoff. `Unknown` is emphatically not here either, and that
    /// is the whole of D-C1: a silence that could not be late is a silence
    /// nobody is ever told about.
    pub fn is_terminal(self) -> bool {
        self.is_stable() || matches!(self, VmPhaseKind::Quarantined)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VmSpec {
    /// Scheduling binding; empty until the scheduler assigns a node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_name: Option<String>,
    /// The same binding one tier up: the cluster the cloud placed this VM on,
    /// empty until it did. One Vm type serves both tiers because the API form
    /// is deliberately the same on both — each tier writes its own binding and
    /// ignores the other's, and neither field is ever set at both ends at once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cluster_name: Option<String>,
    #[serde(default)]
    pub run_strategy: RunStrategy,
    /// What may be done to this VM to get it off a machine that is being
    /// emptied.
    ///
    /// Additive, mutable, `Never` by default — so a drain goes on meaning
    /// exactly what it meant before for every VM ever written, and an
    /// operator opts a VM in rather than discovering that one moved.
    ///
    /// Not the same question as `runStrategy`, and that is why it is its own
    /// field: `runStrategy` is what the owner wants the VM to be DOING, and
    /// this is what the owner will TOLERATE having done to it. A VM that must
    /// keep running through a drain and a VM that may be rebooted to get out
    /// of the way have the same runStrategy and different answers here.
    #[serde(default, skip_serializing_if = "Evacuation::is_never")]
    pub evacuation: Evacuation,
    /// Whose VM this is. Absent = unscoped, which is every VM written before
    /// this milestone and every VM an admin creates without naming one: it
    /// belongs to nobody, only an admin can see it, and it gets no overlay.
    ///
    /// The field lives on both tiers' Vm because the tier below has to know
    /// it too — not to authorize (there is one directory and it is the
    /// cloud's) but to say whose a VM is in `meister vm ls`, and because the
    /// cluster is where the tenant's VNI is injected into the NIC specs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    /// The scheduler class this VM asks for.
    ///
    /// Decision 6 of 6k, the workload half: a node may declare that it takes
    /// only certain classes (`NodeSpec.accepts`), and this is what a VM
    /// answers with. Kubernetes' taint and toleration in one word.
    ///
    /// Empty is the ordinary case and it means [`CLASS_VM`] — read through
    /// [`VmSpec::class`] and never off the field. Storing the empty string
    /// rather than filling in `"vm"` at the edge is what keeps this additive
    /// in the direction that matters: every VM ever written carries no class,
    /// its `spec` is byte-identical to what it was, and the shape comparisons
    /// that guard an update (`vm_shape_unchanged`) see no change at all.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub class: String,
    /// Which clusters this VM may go to: every pair must be present in the
    /// cluster's `spec.labels`. Empty — the default and every VM written
    /// before this — means no constraint at all.
    ///
    /// Two selectors and not one, because a selector names properties of a
    /// MACHINE and those differ by tier: `disk=nvme` is a node's business and
    /// `region=stuttgart` a cluster's. One field matched at both ends would
    /// make a node label into something the cloud tier has to carry, which is
    /// the union-catalogue problem this stack already has once and does not
    /// need twice.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub cluster_selector: BTreeMap<String, String>,
    /// The same, one tier down, against `NodeSpec.labels`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub node_selector: BTreeMap<String, String>,
    /// VMs this one must not sit beside. Matched against the `metadata.labels`
    /// of whatever is already bound to a candidate — so ONE field serves both
    /// tiers, unlike the selectors: "not in the same cluster" and "not on the
    /// same node" are the same sentence about other VMs, asked of different
    /// inventories.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub anti_affinity: Vec<AntiAffinity>,
    /// Agent create fields retained as JSON. Inner fields use snake_case; the
    /// outer resource uses camelCase. `crate::vm_spec` validates the edge shape,
    /// including positive CPU and memory values and unresolved secret references.
    /// Controllers resolve references and injected fields before node delivery;
    /// local image and driver validation remains on the agent.
    #[schemars(with = "agent_api::spec::NewVmSpec")]
    pub vm: serde_json::Value,
}

impl VmSpec {
    /// The class this VM really asks for: what it says, or [`CLASS_VM`] if it
    /// says nothing. The one place the default is applied, so that the stored
    /// object goes on recording what was asked for and every reader — both
    /// tiers' schedulers among them — gets the same answer.
    pub fn class(&self) -> &str {
        if self.class.is_empty() {
            CLASS_VM
        } else {
            &self.class
        }
    }

    /// Find the first volume reference that also supplies an inline disk
    /// definition. Size and image belong to the referenced Volume, so combining
    /// these forms is rejected at both edges. `params` remains allowed because
    /// it configures the attachment rather than the stored bytes.
    pub fn malformed_volume_reference(&self) -> Option<&'static str> {
        let entries = self
            .vm
            .get("volumes")
            .and_then(serde_json::Value::as_array)?;
        let describes = [
            "size_bytes",
            "base_image",
            "base_image_url",
            "base_image_sha256",
            "base_image_uid",
            "driver",
        ];
        entries
            .iter()
            .filter(|e| Self::refers_to_a_volume(e))
            .find_map(|e| {
                describes
                    .into_iter()
                    .find(|field| e.get(field).is_some_and(|v| !v.is_null()))
            })
    }

    /// Whether a `volumes[]` entry REFERS to a `Volume` object rather than
    /// describing a disk to be made for this VM.
    ///
    /// The one distinction the whole hot-plug rule turns on, said once: an
    /// entry with a non-empty `volume` is somebody's disk that outlives the
    /// VM, and everything else is an instance store that came with it.
    fn refers_to_a_volume(entry: &serde_json::Value) -> bool {
        entry
            .get("volume")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|name| !name.is_empty())
    }

    /// The `Secret` this VM's cloud-init reads its user-data from, if it
    /// reads one: `(secret, key)`.
    ///
    /// On `VmSpec` and not in a tier because BOTH tiers ask it — the cloud to
    /// check the tenancy at its edge and to know the reference exists, the
    /// cluster to open it at dispatch — and a second copy of "where does the
    /// reference live in the document" is a second place to get the field
    /// name wrong.
    pub fn user_data_from(&self) -> Option<(String, String)> {
        let from = self.vm.get("cloud_init")?.get("user_data_from")?;
        let secret = from.get("secret")?.as_str()?;
        let key = from.get("key")?.as_str()?;
        (!secret.is_empty() && !key.is_empty()).then(|| (secret.to_string(), key.to_string()))
    }

    /// A cloud-init block that names BOTH a literal user-data and a secret to
    /// read one from.
    ///
    /// 422 rather than a winner, for the reason `from_snapshot` beside
    /// `base_image` gives: two starting points is a spec whose author
    /// believes one of them, and a silent winner hands somebody a guest
    /// configured with the other.
    pub fn user_data_said_twice(&self) -> bool {
        let Some(config) = self.vm.get("cloud_init") else {
            return false;
        };
        let literal = config
            .get("user_data")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|u| !u.is_empty());
        literal && self.user_data_from().is_some()
    }

    /// Referenced Volume names in spec order; inline disks are omitted.
    /// Malformed or absent lists yield no references; edge validation is separate.
    pub fn referenced_volumes(&self) -> Vec<String> {
        self.vm
            .get("volumes")
            .and_then(serde_json::Value::as_array)
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(|e| e.get("volume"))
                    .filter_map(serde_json::Value::as_str)
                    .filter(|name| !name.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Project the immutable portion of `spec.vm` for structural update checks.
///
/// The boot entry and every inline volume retain their content and relative
/// order. Referenced volumes after index zero may be added, removed or edited
/// for hot-plug. All other VM fields remain immutable. Nonobjects and objects
/// without a volume list project to themselves; shape validation is separate.
pub fn frozen_vm_shape(vm: &serde_json::Value) -> serde_json::Value {
    let Some(entries) = vm.get("volumes").and_then(serde_json::Value::as_array) else {
        return vm.clone();
    };
    let frozen: Vec<serde_json::Value> = entries
        .iter()
        .enumerate()
        .filter(|(i, entry)| *i == 0 || !VmSpec::refers_to_a_volume(entry))
        .map(|(_, entry)| entry.clone())
        .collect();
    let mut out = vm.clone();
    out["volumes"] = serde_json::Value::Array(frozen);
    out
}

/// Whether a `spec.vm` edit is one of the edits hot-plug allows: everything
/// equal except `volumes[]` from its second entry on, and there only for
/// entries that name a `Volume`.
///
/// The predicate behind the `spec.vm` row of both tiers' mutability tables.
/// It is a projection compared with itself, which is the plainest way to say
/// the rule — see [`frozen_vm_shape`], which is where the rule actually
/// lives.
pub fn vm_shape_unchanged(current: &serde_json::Value, next: &serde_json::Value) -> bool {
    frozen_vm_shape(current) == frozen_vm_shape(next)
}

/// Whether a binding change is one a CLIENT may make: none at all, or
/// letting it go.
///
/// The predicate behind `Vm.spec.nodeName` at the cluster and
/// `spec.clusterName` at the cloud. Both are server-owned — the scheduler
/// writes them — with one exception, and this is it: a client may set the
/// field to `null`, which means "place this somewhere else".
///
/// It cannot check WHETHER that is allowed right now, because a predicate
/// sees one field and the rule is about the VM's phase. The handler asks the
/// rest (`reschedule needs a stopped vm`); what this opens is only the shape
/// of the edit. That split is deliberate: the table says what KIND of change
/// this field admits, and a condition that depends on another field is not a
/// property of the field.
pub fn unbind_only(current: &serde_json::Value, next: &serde_json::Value) -> bool {
    current == next || next.is_null()
}

/// Whether a number only went UP (or stayed).
///
/// The predicate behind `Volume.spec.sizeGib`, and the reason
/// `Owned::structural` takes a PAIR rather than a projection: "may only grow"
/// is a fact about two numbers together, and no projection of one of them can
/// state it.
///
/// A value that is not a number on either side falls back to equality —
/// absent, `null`, a string a client sent by mistake. That is the same
/// direction every other unknown takes in this file: silence never widens a
/// rule.
pub fn grows_only(current: &serde_json::Value, next: &serde_json::Value) -> bool {
    match (current.as_u64(), next.as_u64()) {
        (Some(was), Some(now)) => now >= was,
        _ => current == next,
    }
}

/// "Do not place me with these." One label set, and how hard it is meant.
///
/// `required` defaults to TRUE, and that is the safe direction: somebody who
/// writes an anti-affinity term and forgets the flag meant to keep two
/// replicas apart, and a preference that silently was not one is a failure
/// nobody sees until the machine it was guarding against goes down.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AntiAffinity {
    /// Every pair must be present in another VM's `metadata.labels` for it to
    /// count as one of the VMs meant. An EMPTY selector matches every VM, and
    /// that is a real ask — "not with anything else at all".
    #[serde(default)]
    pub selector: BTreeMap<String, String>,
    /// Hard: a candidate that collides is not a candidate. False makes it a
    /// preference, honoured when it can be and dropped when honouring it
    /// would mean not placing the VM at all.
    #[serde(default = "required_default")]
    pub required: bool,
}

fn required_default() -> bool {
    true
}

/// Where one line of `VmStatus.addresses` came from.
///
/// A closed set and a word rather than a bare pair of optional fields,
/// because the two lines mean different things and a client has to be able to
/// branch on which one it is holding without guessing from which field is
/// filled.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum VmAddressKind {
    /// A hardware address the NODE gave one of this VM's taps.
    #[default]
    Mac,
    /// A floating address this cloud has pointed at this VM.
    FloatingIp,
}

/// One thing the control plane knows about reaching a VM.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VmAddress {
    pub kind: VmAddressKind,
    /// The nic this is about, as the VM's own spec names it. Empty on a
    /// floating-ip line: a floating address is pointed at the VM and not at
    /// one of its interfaces.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub nic: String,
    /// The hardware address, on a `Mac` line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    /// The address, on a `FloatingIp` line. Never filled on a `Mac` line —
    /// see `VmStatus.addresses`: only the guest knows that one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct VmStatus {
    /// The phase, with the reason it is that phase and since when.
    ///
    /// Flat on the wire — `phase`, `reason`, `message`, `since` as siblings
    /// right here — so every client that reads `status.phase` as a string
    /// goes on reading it as a string. See `resources::phase`.
    #[serde(flatten)]
    pub(super) phase: VmPhase,
    /// The last word the tier below said about the guest — a node's at the
    /// cluster, a cluster's at the cloud — and this tier's own conclusions
    /// beside it (a create that went out, a machine that refused, a holder
    /// that let go).
    ///
    /// **The same type and the same derivation at both altitudes**, which is
    /// what keeps `Running` from meaning two things one hop apart. An empty
    /// `node` on it is this tier's own word and can never make the VM
    /// `Running`, `Stopped` or `Paused`: only a machine that has the guest
    /// may say what it is doing. See `VmReported`.
    ///
    /// `None` on a VM nobody has said anything about — a fresh one, and one
    /// whose binding has just been let go.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reported: Option<VmReported>,
    /// That the machine or cluster holding this VM has stopped answering, as
    /// a reconcile pass saw it.
    ///
    /// The fact behind `Unknown`, and the one D-C1 is about: a node fell out
    /// of the lab and nothing anywhere said so. The pass that reads the lease
    /// is the only party that knows, so it writes this down; `settle` turns
    /// it into `Unknown { Silent }` and NOTHING turns that into anything else
    /// (`unknown_needs_its_holder`). One report from the holder clears it.
    ///
    /// It is also what the stuck deadline measures: `Unknown` since four and
    /// a half days is a number in Prometheus because this field says when.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub silence: Option<VmSilence>,
    /// What the scheduler last said about a VM it could not place.
    ///
    /// Its own fact and not part of `reported`, because it answers a
    /// different question and must not answer the first one: this pass says
    /// WHY a VM is waiting, it does not decide what the VM is doing. A
    /// running guest whose newly added disk is not ready yet is still
    /// running.
    ///
    /// Cleared by the binding: a VM that has been placed must not go on
    /// carrying the sentence that said it could not be.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placement: Option<VmPlacement>,
    /// The last `metadata.generation` this object's controller ACTED on.
    ///
    /// Kubernetes' half of the pair, and the whole of what it says is:
    /// `observedGeneration < generation` means the spec was changed after the
    /// controller last did something about it. It is not "the change has
    /// taken effect" — nothing here can promise that — it is "the change has
    /// been picked up", which is the honest thing a control plane knows about
    /// itself.
    ///
    /// `0` on an object nothing has been dispatched for yet, and on every
    /// object written before this field existed.
    #[serde(default)]
    pub observed_generation: u64,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_name: Option<String>,
    /// Which cluster observed this phase — the cloud tier's counterpart to
    /// nodeName, and the only thing the cloud can honestly say about where a
    /// VM is: the node underneath it belongs to the cluster's own picture.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cluster_name: Option<String>,
    /// Time of the latest observed state change, not heartbeat freshness.
    /// Unchanged reports leave it intact. `mirror::is_current` uses it to reject
    /// reports older than a command; node heartbeat state determines freshness.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<DateTime<Utc>>,
    /// Known access information: floating addresses assigned by the cloud and
    /// tap MACs reported by nodes. Guest-configured IP addresses are not
    /// discovered. The list can be empty until a node reports.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<VmAddress>,
    /// The referenced volumes of this VM's spec, and whether the NODE says it
    /// has each one open.
    ///
    /// The evidence half of hot-plug. `spec.vm.volumes[]` is the intent, this
    /// is the observation, and `observedGeneration` closes only when the two
    /// agree — which is why the two are separate fields rather than one
    /// boolean: an operator watching an attach wants to know WHICH disk is
    /// not there yet, and "generation 3, observed 2" does not say.
    ///
    /// One entry per referenced entry of the spec, in spec order. Empty for a
    /// VM with only inline disks, which is every VM before this milestone —
    /// there is nothing to observe about an instance store that was made with
    /// the VM.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub volumes: Vec<VolumeAttachmentStatus>,
    /// How often this VM has been placed again after a client let its binding
    /// go.
    ///
    /// Bookkeeping an operator reads and nothing decides on: a reschedule
    /// leaves no other trace once it is done — the VM is simply somewhere
    /// else — and "did this move, or was it always here" is the first
    /// question somebody asks of a VM that is not where they left it.
    ///
    /// Zero on every VM that has never moved, which is every VM before this
    /// milestone.
    #[serde(default, skip_serializing_if = "u32_is_zero")]
    pub reschedules: u32,
    /// Nodes that refused to serve this VM at all, and until when they are
    /// not candidates for it.
    ///
    /// A node that answered `CannotServe` will answer it again — the refusal
    /// is about the node's configuration, not about the attempt — so placing
    /// the VM there again would be a loop of one create per pass. Recorded
    /// with an EXPIRY rather than for ever, because the answer can change:
    /// an operator adds the driver, the agent is rolled out, and the node
    /// becomes a candidate again without anybody having to clear a field.
    ///
    /// Empty for almost every VM, which is why it is skipped when it is.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub refused_by: Vec<Refusal>,
    /// Requeue bookkeeping (see `requeue`): how often the reconciler has
    /// kicked this Failed VM, and when it last did (or first saw the phase).
    /// Reset the moment the phase leaves Failed.
    #[serde(default, skip_serializing_if = "u32_is_zero")]
    pub requeue_attempts: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_requeue: Option<DateTime<Utc>>,
    /// A move by restart that is in flight, and how far it has got.
    ///
    /// The mark the drain sets, and the reason it is on `status` rather than
    /// being a field of `spec`: a drain is not a change to what the OWNER
    /// asked for. `runStrategy` stays `Running` for the whole of it — the VM
    /// is meant to be running, it is simply not running right now — and
    /// without this mark the ordinary level-triggered lifecycle would read
    /// "wants Running, is Stopped" and start the VM again on the very machine
    /// being emptied, one pass after the drain stopped it.
    ///
    /// It also has to survive a controller restart, because the middle of
    /// this operation is a VM that is deliberately off. A replica that came
    /// back without it would start that VM where it stood.
    ///
    /// `None` for every VM that is not being moved, which is nearly all of
    /// them and every VM written before this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evacuating: Option<Evacuating>,
}

/// A restart-move in flight: which machine it is leaving, and which half of
/// the move it is in.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Evacuating {
    /// The node (or, at the cloud, the cluster) being emptied. Kept so that
    /// the mark can be cleared on the one condition that means the move
    /// landed: the VM is bound somewhere ELSE.
    pub from: String,
    /// One of [`EvacuationStep::as_str`].
    pub step: String,
    pub since: DateTime<Utc>,
}

/// The two halves of a move by restart.
///
/// Two and not four, because the second half is not this operation's work:
/// once the binding has fallen, the reschedule that already exists does the
/// destroying, the waiting and the placing, and the ordinary lifecycle starts
/// the VM because `runStrategy` never stopped saying Running. So the mark
/// only has to say "do not start it yet", and then "we are waiting for a new
/// binding".
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum EvacuationStep {
    /// The guest is being asked to power off, with the node's grace period.
    /// The one step in which something deliberately contradicts
    /// `runStrategy`.
    Stopping,
    /// It is off and the binding has been let go. From here it is an
    /// ordinary reschedule, and the mark's only job is to be cleared when a
    /// new binding appears.
    Moving,
}

impl EvacuationStep {
    pub const ALL: [EvacuationStep; 2] = [EvacuationStep::Stopping, EvacuationStep::Moving];

    pub fn as_str(self) -> &'static str {
        match self {
            EvacuationStep::Stopping => "Stopping",
            EvacuationStep::Moving => "Moving",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|st| st.as_str() == s)
    }
}

/// One node's "I cannot serve this VM", and when it stops counting.
///
/// The sentence is the NODE's own, kept verbatim: "no volume driver
/// lvm-thin", "this node has no record of volume …". It is what an operator
/// reads to find out why a VM moved, and inventing a summary here would lose
/// the one piece of information the node had and this tier does not.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Refusal {
    pub node: String,
    /// What the node said.
    pub message: String,
    /// After this, the node is a candidate again. See `VmStatus::refused_by`.
    pub until: DateTime<Utc>,
}

/// One referenced disk of a VM, and whether the node has it open.
///
/// `name` and not the uid, because this is what a person reads: the uid is
/// what travels on the wire and the name is what they typed. The two are
/// resolved where the objects are, which is here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct VolumeAttachmentStatus {
    pub name: String,
    /// What the NODE said, not what it was told. `false` on a disk that was
    /// asked for and has not arrived, and on every entry of a VM whose node
    /// runs an agent from before the field existed — which reads as "not
    /// confirmed", never as "detached".
    pub attached: bool,
}

fn u32_is_zero(n: &u32) -> bool {
    *n == 0
}

/// Nobody has heard from the machine or cluster holding a VM.
///
/// Data and not the finished sentence, so that both tiers word it the same
/// way and a test can assert on the instant rather than on prose.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VmSilence {
    /// What stopped answering, with its kind — `node agent-1a`,
    /// `cluster cluster-1`. The whole phrase, because the two tiers hold
    /// different kinds of holder and neither should reword the other's.
    pub holder: String,
    /// When it last reported, out of its lease. `None` = it never has.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_heard: Option<DateTime<Utc>>,
    /// When this tier first noticed. What the stuck deadline measures.
    pub since: DateTime<Utc>,
}

/// What the scheduler said about a VM it could not place.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VmPlacement {
    /// The category, out of `PendingReason::category` — a WALL (`Unplaced`)
    /// or a WAIT (`NotReady`). The twelve scheduler words themselves stay in
    /// the sentence and in `PendingTally`'s metric label, which is counted
    /// per pass and not read off this field.
    pub reason: VmReason,
    /// The sentence, which counts candidates and names capabilities. This is
    /// what an operator reads, and no closed word replaces it.
    pub message: String,
    pub at: DateTime<Utc>,
}

/// Derive the same phase at both controller tiers, in precedence order:
///
/// 1. A silent holder makes the state Unknown.
/// 2. No binding and no reported holder means Pending. A reported holder
///    preserves evidence about a guest even after its desired binding clears.
/// 3. Use the last observation; Running, Stopped and Paused require a node.
/// 4. Otherwise wait for placement or a node report, retaining the explanation.
pub fn settle_vm(spec: &VmSpec, status: &VmStatus) -> VmPhase {
    // Rule 1.
    if let Some(silence) = &status.silence {
        return VmPhase::new(
            VmPhaseKind::Unknown,
            VmReason::Silent,
            Some(match silence.last_heard {
                Some(last) => format!(
                    "{} last reported {}, more than {}s ago; what the guest is doing is not \
                     known here",
                    silence.holder,
                    last.to_rfc3339(),
                    crate::heartbeat::HEARTBEAT_TIMEOUT_SECS
                ),
                None => format!(
                    "{} has never reported, more than {}s ago; what the guest is doing is not \
                     known here",
                    silence.holder,
                    crate::heartbeat::HEARTBEAT_TIMEOUT_SECS
                ),
            }),
            UNSTAMPED,
        );
    }
    let said = status.reported.as_ref();
    let waiting = |reason: VmReason, message: Option<String>| {
        VmPhase::new(VmPhaseKind::Pending, reason, message, UNSTAMPED)
    };
    let scheduler = status
        .placement
        .as_ref()
        .map(|p| (p.reason, Some(p.message.clone())));
    // Rule 2. A binding at either tier, and a holder named on the status at
    // either tier: the cluster writes `nodeName`, the cloud writes both.
    let claimed = spec.node_name.is_some()
        || spec.cluster_name.is_some()
        || status.node_name.is_some()
        || status.cluster_name.is_some();
    if !claimed {
        let (reason, message) = scheduler
            .or_else(|| said.map(|r| (r.reason, r.message.clone())))
            .unwrap_or((VmReason::AwaitingNode, Some("not placed yet".to_string())));
        return waiting(reason, message);
    }
    // Rule 3. A peer's word counts only while `spec` still names it as the
    // holder — Astra finding S20, 2026-09-23. `status.reported` stays on the
    // object until a fresh report replaces it, and a vm whose SPEC has since
    // been rebound to somebody else must not go on reading that old word as
    // current; the empty-`node` case (`here`) is this tier's own conclusion
    // and carries no peer to compare. Checked against `spec` and not
    // `status.nodeName`/`status.clusterName`: those two lag a rebind on
    // purpose (`a_guest_a_node_still_holds_is_not_nowhere`) and are exactly
    // the case this must NOT refuse — the old holder's word is still good
    // until spec itself points elsewhere.
    let stale_holder = said.is_some_and(|r| {
        !r.node.is_empty()
            && (spec
                .node_name
                .as_deref()
                .is_some_and(|bound| bound != r.node)
                || spec
                    .cluster_name
                    .as_deref()
                    .is_some_and(|bound| bound != r.node))
    });
    if !stale_holder && let Some(phase) = said.and_then(VmReported::phase) {
        return phase;
    }
    // Rule 4.
    let (reason, message) = scheduler.unwrap_or_else(|| {
        let holder = status
            .node_name
            .as_deref()
            .or(status.cluster_name.as_deref())
            .or(spec.node_name.as_deref())
            .or(spec.cluster_name.as_deref())
            .unwrap_or("nobody");
        (
            VmReason::AwaitingNode,
            Some(format!("{holder} has not reported yet")),
        )
    });
    waiting(reason, message)
}

pub type Vm = Object<VmSpec, VmStatus>;

/// A VM, with the finalizer that makes teardown the one path out.
pub fn new_vm(name: &str, spec: VmSpec) -> Vm {
    let mut vm = Vm::declare(name, spec);
    vm.metadata
        .finalizers
        .push("meister.io/teardown".to_string());
    vm
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::Resource;

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_800_000_000 + secs, 0).expect("an instant")
    }

    fn vm(node: Option<&str>) -> Vm {
        new_vm(
            "web-1",
            VmSpec {
                class: Default::default(),
                cluster_selector: Default::default(),
                node_selector: Default::default(),
                anti_affinity: Vec::new(),
                node_name: node.map(str::to_string),
                cluster_name: None,
                run_strategy: RunStrategy::Running,
                evacuation: Default::default(),
                tenant: None,
                vm: serde_json::json!({ "vcpus": 1 }),
            },
        )
    }

    /// The table, in the order the four rules run — and the order is the
    /// whole content of the derivation.
    #[test]
    fn what_is_known_about_a_vm_is_what_the_vm_is() {
        // Rule 4, and the state nothing used to have a word for: created,
        // bound, and the create has not gone out.
        let mut fresh = vm(Some("agent-1a"));
        fresh.settle(at(0));
        assert_eq!(fresh.status.phase().kind(), VmPhaseKind::Pending);
        assert_eq!(
            fresh.status.phase().reason(),
            Some(VmReason::AwaitingNode),
            "a VM nobody has reported on says what it is waiting for"
        );
        assert_eq!(
            fresh.status.phase().message(),
            Some("agent-1a has not reported yet")
        );

        // Rule 2: nothing claims it. The scheduler says why.
        let mut nowhere = vm(None);
        nowhere.settle(at(0));
        assert_eq!(nowhere.status.phase().message(), Some("not placed yet"));
        nowhere.status.placement = Some(VmPlacement {
            reason: VmReason::Unplaced,
            message: "no candidate has room (3 looked at)".to_string(),
            at: at(0),
        });
        nowhere.settle(at(0));
        assert_eq!(nowhere.status.phase().kind(), VmPhaseKind::Pending);
        assert_eq!(nowhere.status.phase().reason(), Some(VmReason::Unplaced));
        assert_eq!(
            nowhere.status.phase().message(),
            Some("no candidate has room (3 looked at)")
        );

        // Rule 3: the node's own word, and its own reason — `VmmGone` and
        // `BackendGone` are two different problems and used to be one word.
        let mut broken = vm(Some("agent-1a"));
        broken.status.reported = Some(VmReported::by(
            "agent-1a",
            VmPhaseKind::Quarantined,
            VmReason::BackendGone,
            Some("the vhost-user backend died under a live vmm".into()),
            at(0),
        ));
        broken.settle(at(0));
        assert_eq!(broken.status.phase().kind(), VmPhaseKind::Quarantined);
        assert_eq!(broken.status.phase().reason(), Some(VmReason::BackendGone));

        // Rule 1: the machine has stopped answering, so the last word is no
        // longer known to be true. D-C1.
        let mut lost = vm(Some("agent-1a"));
        lost.status.reported = Some(VmReported::by(
            "agent-1a",
            VmPhaseKind::Running,
            VmReason::Unrecorded,
            None,
            at(0),
        ));
        lost.settle(at(0));
        assert_eq!(lost.status.phase().kind(), VmPhaseKind::Running);
        lost.status.silence = Some(VmSilence {
            holder: "node agent-1a".to_string(),
            last_heard: Some(at(0)),
            since: at(60),
        });
        lost.settle(at(60));
        assert_eq!(lost.status.phase().kind(), VmPhaseKind::Unknown);
        assert_eq!(lost.status.phase().reason(), Some(VmReason::Silent));
        let said = lost.status.phase().message().expect("a sentence");
        assert!(said.contains("node agent-1a"), "{said}");
        assert!(said.contains("not known here"), "{said}");
    }

    /// A guest that is still RUNNING on a node this tier has unbound does not
    /// read as nowhere.
    ///
    /// The second half of rule 2, and the reason it is two conditions rather
    /// than one: `unbind` clears `spec.nodeName` while the old machine still
    /// has the VM, and it is `status.nodeName` that says so. A VM is nowhere
    /// only when nobody claims it at all.
    #[test]
    fn a_guest_a_node_still_holds_is_not_nowhere() {
        let mut leaving = vm(None);
        leaving.status.node_name = Some("agent-1a".to_string());
        leaving.status.reported = Some(VmReported::by(
            "agent-1a",
            VmPhaseKind::Running,
            VmReason::Unrecorded,
            None,
            at(0),
        ));
        leaving.settle(at(0));
        assert_eq!(
            leaving.status.phase().kind(),
            VmPhaseKind::Running,
            "the old node still has the guest"
        );

        // And when it lets go, the VM is waiting to be placed.
        leaving.status.node_name = None;
        leaving.status.reported = Some(VmReported::here(
            VmPhaseKind::Pending,
            VmReason::Unbound,
            Some("node agent-1a let go; waiting to be placed".into()),
            at(60),
        ));
        leaving.settle(at(60));
        assert_eq!(leaving.status.phase().kind(), VmPhaseKind::Pending);
        assert_eq!(leaving.status.phase().reason(), Some(VmReason::Unbound));
    }

    /// A resting word demands a machine. `Running`, `Stopped` and `Paused`
    /// are claims about a guest, and a dispatch is not one — F16's rule on
    /// the object it matters most on.
    #[test]
    fn this_tier_cannot_conclude_that_a_guest_is_running() {
        for resting in [
            VmPhaseKind::Running,
            VmPhaseKind::Stopped,
            VmPhaseKind::Paused,
        ] {
            let mut invented = vm(Some("agent-1a"));
            invented.status.reported =
                Some(VmReported::here(resting, VmReason::Dispatched, None, at(0)));
            invented.settle(at(0));
            assert_eq!(
                invented.status.phase().kind(),
                VmPhaseKind::Pending,
                "{resting:?} with nobody behind it"
            );
        }
    }

    /// The scheduler explains a wait; it does not create one.
    ///
    /// A running guest whose newly added disk is not ready yet is still
    /// running, and that is why `placement` is its own fact rather than part
    /// of the word: `hot_plug` writes it about a VM that is up.
    #[test]
    fn the_scheduler_explains_a_wait_and_does_not_make_one() {
        let mut running = vm(Some("agent-1a"));
        running.status.reported = Some(VmReported::by(
            "agent-1a",
            VmPhaseKind::Running,
            VmReason::Unrecorded,
            None,
            at(0),
        ));
        running.settle(at(0));
        running.status.placement = Some(VmPlacement {
            reason: VmReason::NotReady,
            message: "volume data-2 is Provisioning on agent-1a".to_string(),
            at: at(10),
        });
        running.settle(at(10));
        assert_eq!(running.status.phase().kind(), VmPhaseKind::Running);
        assert_eq!(running.status.phase().since(), at(0));
    }

    /// `Unknown` is never promoted, however long it stands
    /// (`unknown_needs_its_holder`). The only exit is the holder speaking.
    #[test]
    fn nothing_turns_an_unknown_into_a_verdict() {
        let mut lost = vm(Some("agent-1a"));
        lost.status.silence = Some(VmSilence {
            holder: "node agent-1a".to_string(),
            last_heard: Some(at(0)),
            since: at(60),
        });
        // A failure reported before the silence, a requeue count, four days:
        // none of it is evidence about a guest nobody has looked at.
        lost.status.reported = Some(VmReported::by(
            "agent-1a",
            VmPhaseKind::Failed,
            VmReason::VmmGone,
            None,
            at(0),
        ));
        lost.status.requeue_attempts = 9;
        lost.settle(at(60));
        assert_eq!(lost.status.phase().kind(), VmPhaseKind::Unknown);
        lost.settle(at(60 + 4 * 24 * 3600));
        assert_eq!(lost.status.phase().kind(), VmPhaseKind::Unknown);
        assert_eq!(
            lost.status.phase().since(),
            at(60),
            "and it has been Unknown since the silence, which is what the deadline measures"
        );

        // The holder speaks: whatever it says replaces the absence.
        lost.status.silence = None;
        lost.settle(at(60 + 4 * 24 * 3600));
        assert_eq!(lost.status.phase().kind(), VmPhaseKind::Failed);
    }
}

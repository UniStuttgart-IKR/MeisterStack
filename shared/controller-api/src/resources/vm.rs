// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The `Vm` kind: what a client asks for, and what the control
//! plane says about it. Moved out of `resources.rs` unchanged.

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
    /// Why a VM is what it is — the CATEGORY behind the sentence, in a form a
    /// program can hold and a metric label can carry.
    ///
    /// Eight, and every one of them is a word this code already said
    /// somewhere: `Unplaced` and `NotReady` are the twelve `PendingReason`
    /// categories split where the split changes what an operator DOES (a
    /// wall, or a wait) — see `PendingReason::category`; `Unbound` is the two
    /// ingest paths that say "let go; waiting to be placed"; `Dispatched` is
    /// the anticipation the reconciler writes when a create goes out;
    /// `Refused` is `CannotServe` and the cloud's refusal of a create;
    /// `Reported` is a node's or a cluster's own word arriving on the status
    /// road; `Silent` is `unheard_of` and its counterpart at the cloud.
    ///
    /// The sentence is not replaced by any of this and never will be: it
    /// counts candidates and names capabilities, which is what an operator
    /// reads. This is the closed set behind it, so that "how many VMs are
    /// waiting, and why" is a time series rather than a string.
    VmReason [8] {
        /// Nobody recorded one.
        ///
        /// Not a failure of this enum but the honest value in two cases: a
        /// phase stored before struktur 4, and a writer that genuinely has
        /// nothing categorical to say. The next pass replaces it — which is
        /// decision 6 of the brief, and the reason there is no migration
        /// code anywhere in this change.
        #[default]
        Unrecorded => "Unrecorded",
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
        /// The tier below's own word about the guest, verbatim in the
        /// message. The commonest reason behind `Failed` and the only one
        /// behind `Quarantined`.
        Reported => "Reported",
        /// Nobody has heard from the machine holding it for longer than the
        /// heartbeat allows — a node at the cluster, a cluster at the cloud.
        /// ONE word for both, and the sentence says which ("node X last
        /// reported …"). The brief asks for two; there are eight slots and
        /// this is the pair whose difference is already in the sentence.
        Silent => "Silent",
    }
}

phases! {
    /// What this control plane says a VM is doing.
    VmPhase / VmPhaseKind / VmReason / VmPhaseWire [8] {
        Pending { reason, message, since } => "Pending",
        Provisioning { reason, message, since } => "Provisioning",
        Running { message, since } => "Running",
        Stopped { message, since } => "Stopped",
        Paused { message, since } => "Paused",
        Failed { reason, message, since } => "Failed",
        Quarantined { reason, message, since } => "Quarantined",
        /// Nobody has heard from the machine this VM is on for longer than the
        /// heartbeat allows, so nothing here knows what the guest is doing.
        ///
        /// NOT `Failed`, and the difference is the whole reason this variant
        /// exists: `Failed` is a claim that something went wrong, and nothing
        /// went wrong that anybody can point at — the guests on a node whose
        /// agent was killed keep running, which is exactly what the mini-chaos
        /// run found on manacor (agent dead 20 h, eleven guests alive). What is
        /// true is only that the control plane has stopped knowing, and that is
        /// what this says.
        ///
        /// It is also not a `Failed` because of what `Failed` COSTS: it is the
        /// phase the requeue curve acts on, and requeueing a VM whose node simply
        /// stopped talking would be this tier repairing something it has no
        /// evidence is broken.
        ///
        /// One report from the node replaces it with whatever is true, and that
        /// is the whole exit — there is no timer that promotes it to anything.
        /// `unknown_needs_its_holder`: nothing in this stack turns this into
        /// `Failed`, however long it stands. What a deadline buys is an event
        /// and a metric (see `stuck`), not a verdict.
        ///
        /// It is PARSED as well as written: an agent that comes back reports a
        /// real phase, but a CLUSTER relaying its own stored phase to the
        /// cloud sends this word, and a tier that rejected it would keep
        /// showing Running for a VM its own cluster has given up on.
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
    /// The agent's create document as raw JSON, carried and not read.
    ///
    /// Carried, still: nothing here interprets it, and a field added to it at
    /// the node travels through both tiers without a change to this struct.
    /// What DID change is that its shape is now published — `/schemas` shows
    /// the fields, derived from `agent_api::spec::NewVmSpec` itself, so a form
    /// can list them instead of copying them out of a guide. The type is
    /// named only for the schema and for the edge check; the value stays a
    /// `Value` on the way through.
    ///
    /// The boundary that survives is the one that matters: this control plane
    /// still knows nothing about sizing, images on disk or drivers. It knows
    /// the FIELDS, which are not a secret.
    ///
    /// Note the snake_case inside it — `vcpus`, `memory_mib`, `base_image`,
    /// `cloud_init` — while everything outside is camelCase. It is another
    /// crate's document, and it keeps its own spelling.
    ///
    /// What IS checked here: `vcpus >= 1` and `memory_mib >= 1`, because
    /// those are structural rather than a question of size. See
    /// `crate::vm_spec`.
    ///
    /// This is the one field of any spec in this file whose contents
    /// `deny_unknown_fields` does not reach — it is a `Value`, so serde has
    /// nothing to compare against. The rule is not missing, it is made one
    /// step later: `vm_spec::check` deserialises it into `NewVmSpec`, which
    /// carries the attribute itself.
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

    /// The `Volume` objects this VM's disks REFER to, by name and in order.
    ///
    /// The one field of `spec.vm` this control plane reads, and the exception
    /// is deliberate rather than a crack in the boundary. Everything else in
    /// that document describes something the NODE does, so carrying it
    /// unopened is exactly right; `volumes[].volume` describes something only
    /// this tier can do — resolve a name to an object, check whose it is,
    /// find out where its bytes are and place the VM accordingly. A node
    /// cannot do any of that, so the field would be meaningless if it were
    /// carried unopened.
    ///
    /// One string per referring entry, and an entry that refers to nothing is
    /// simply absent from the answer: an inline disk is ephemeral and this
    /// tier has nothing to say about it. Empty for every VM ever written
    /// before the field existed.
    ///
    /// Total by construction — a spec that is not an object, has no
    /// `volumes`, or whose entries are not objects yields an empty list
    /// rather than an error. Whether the document is a VM at all is
    /// `check_vm_shape`'s question at the edge, and asking it twice in two
    /// places is how the two answers start to differ.
    /// The first `volumes[]` entry that both NAMES a volume and describes
    /// one, if there is such an entry.
    ///
    /// A referenced volume has its size and its base image already — they
    /// belong to the disk that exists — so an entry that says both is an
    /// entry whose author believes one of the two. The wrong belief is the
    /// one where a 10 GiB disk silently stays the 1 GiB somebody typed, so
    /// this is a refusal and not a field that quietly wins.
    ///
    /// Checked at the API edge as well as at the node. The node's refusal is
    /// the one that cannot be bypassed and stays; this one is the one a
    /// PERSON sees, while they are still holding the request, instead of
    /// finding a Failed VM later.
    ///
    /// `params` is the exception and is not listed: attach options are a
    /// property of the connection rather than of the bytes, and two VMs of
    /// one volume over time may mount it under two names.
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

/// The part of `spec.vm` an update may not touch — everything, except
/// `volumes[]` from its SECOND entry on, and there only the entries that
/// refer to a `Volume` object.
///
/// This is the projection behind the `spec.vm` row of both tiers' mutability
/// tables (`Owned::structural`), and it is the whole of the hot-plug rule:
///
///   * **the boot entry never moves.** `volumes[0]` is what the guest boots
///     from; a VM whose root disk was swapped underneath it is not the same
///     VM, and there is no moment at which a running guest would survive it.
///   * **an inline entry never moves either** — not added, not removed, not
///     edited. An inline entry is an instance store: it came into being with
///     the VM and goes with it, and one does not plug an instance store in
///     afterwards. It stays in the projection wherever it sits, so its ORDER
///     among the other inline entries is frozen too.
///   * **referenced entries from index 1 on are free.** Adding one is the
///     attach, leaving one out is the detach, and what follows is the
///     reconciler's business rather than a verb of its own — KubeVirt
///     deprecated `addvolume` in 1.6 for exactly this reason.
///
/// Everything else in the document — vcpus, memory, boot, nics, devices,
/// cloud-init — is copied into the projection unchanged and therefore stays
/// immutable, which is what it was before any of this.
///
/// Total, like every other reader of this document: a `spec.vm` that is not
/// an object, or has no `volumes`, projects to itself, and two of those
/// compare exactly as they did before. Whether the document is a VM at all is
/// the edge's question and is asked in one place.
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
    /// When the phase above last CHANGED, as this tier saw it.
    ///
    /// The only field in this struct that had no doc comment, and the mistake
    /// that cost was reading it as a freshness stamp. It is not one and must
    /// not become one: `observe` drops a report that says what is already
    /// stored, so a VM that has been happily Running for a fortnight carries
    /// a fortnight-old instant — the lab showed `cloud-probe` at thirteen
    /// days on a node that was answering every ten seconds. Turning it into a
    /// per-report write would be an etcd revision per VM per ten seconds, and
    /// a vm watch woken by every one of them, to record that nothing
    /// happened.
    ///
    /// What it IS for is ordering: `mirror::is_current` uses it as the floor
    /// a report has to clear, so a status built before the last command
    /// cannot be read as describing the world after it.
    ///
    /// Whether a VM's phase is still TRUE is a question about its node, and
    /// the node's `status.lastHeartbeat` is where it is answered — see
    /// `unheard_of` in the cluster reconciler.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<DateTime<Utc>>,
    /// What the control plane knows about how to reach this VM.
    ///
    /// Named for exactly what it is, because the honest answer is smaller
    /// than "the addresses of this vm": the IP a guest configured itself is
    /// known to the guest and to nobody here. There is no agent inside the
    /// guest and there will not be one, so a list called `ipAddresses` would
    /// either stay empty for ever or become a lie the first time DHCP handed
    /// out something else.
    ///
    /// Two things ARE known and both belong in this list. A floating address
    /// pointed at this VM, which is this cloud's own object and needs
    /// nobody's report. And the MAC of every tap a node made, which is what a
    /// DHCP lease is looked up by and what an operator matches against `ip
    /// neigh` — reported by the node, so absent until one reports it, and
    /// absent for as long as the node's agent predates `NicReport`.
    ///
    /// Empty is honest and is the state of a VM nobody has said anything
    /// about yet.
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

pub type Vm = Object<VmSpec, VmStatus>;

/// A VM, with the finalizer that makes teardown the one path out.
pub fn new_vm(name: &str, spec: VmSpec) -> Vm {
    let mut vm = Vm::declare(name, spec);
    vm.metadata
        .finalizers
        .push("meister.io/teardown".to_string());
    vm
}

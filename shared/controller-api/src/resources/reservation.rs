// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The `CapacityReservation` kind: room held on a node for a guest that is on
//! its way there and is not counted anywhere else yet — the claim half of the
//! one capacity commit both roads to a node go through.

use super::*;

/// How long a placement's claim may stand before it is read as abandoned.
///
/// A placement holds its claim for the length of one confirmation and one
/// binding — a handful of round trips, milliseconds on a healthy store and
/// bounded by the store's request timeout on a sick one. A claim that has
/// stood for a minute with its guest still unbound was written by a process
/// that is not coming back for it, and the reaper takes it. Generous on
/// purpose: reaping EARLY is safe — the binding is refused once its claim is
/// gone, see `EtcdStore::update_if_standing` — so the only cost of a long
/// bound is that a crashed placement's room comes back a minute late, and
/// the only cost of a short one would be a slow placement being made to try
/// again.
pub const STALE_PLACEMENT_AFTER_SECS: i64 = 60;

/// The prefix a placement's claim is named under, ahead of the guest's uid.
const PLACEMENT_CLAIM_PREFIX: &str = "place-";

/// Who is holding this room: which of the two roads to a node the guest is
/// on.
///
/// The two are told apart because they are released by different facts. A
/// migration's promise is live while its migration is being carried, and a
/// placement's while its guest is unbound and the claim is young — the
/// reaper reads this field to know which question to ask. `Migration` is the
/// default so that a promise written before this field existed reads as
/// what it was.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum Claimant {
    /// A live migration's destination, held from `prepare` until the guest's
    /// binding moves there. See `migration::reserve`.
    #[default]
    Migration,
    /// An ordinary placement, held from the scheduler's decision until the
    /// binding is written. See `placement::place`.
    Placement,
}

/// Room promised on one machine to one guest that has not arrived.
///
/// **What this is for.** `Candidate::free` is derived: a node's allowance
/// under overcommit minus the guests BOUND to it — `spec.nodeName` — summed
/// per pass out of the VM objects and never stored. Two things can be on
/// their way to a machine without being bound to it: a live migration's
/// guest, which stays bound to the source until the transfer has finished,
/// and a guest the scheduler has just decided on and not yet written the
/// binding for. A decision measured against the derived number alone cannot
/// see either of them. This object is that guest, counted where it is going.
///
/// **The one commit, and both roads through it.** A guest reaches a node by
/// exactly two roads — an ordinary placement and a live migration — and both
/// take the same four steps in the same order against the same store:
///
///   1. CLAIM. A create-only write of this object. The key is a function of
///      the move — the migration's name for a migration, `place-<vm uid>`
///      for a placement — so "exactly one claim for this move" is a fact of
///      the store and not a convention, and a second replica that reaches
///      the same step finds the room already spoken for by this very move
///      rather than booking it twice.
///   2. CONFIRM. [`crate::capacity::claim_holds`]: ONE consistent reading of
///      the node, the VMs and the reservations — the two listings out of one
///      etcd revision — and the question "does my claim fit in the allowance,
///      minus the guests bound here, minus every claim on this node written
///      BEFORE mine". The order is etcd's own `mod_revision`, so two claims
///      against one slot reach the same verdict on every replica, and the
///      later one yields. A reading that fails is a verdict that fails and
///      never one that passes (Astra R3-F04).
///   3. BIND. `spec.nodeName`, by compare-and-swap on the VM object — and for
///      a placement only while the claim still stands as it was written,
///      in the same transaction (`EtcdStore::update_if_standing`). A claim
///      that was reaped, released or never confirmed cannot become a
///      binding.
///   4. RELEASE. After the binding and never before it: a guarded delete on
///      the claim's own revision. Between 3 and 4 the guest is counted twice
///      — bound and promised — which is the safe direction and lasts one
///      round trip.
///
/// **The invariant.** At every revision of the store, a guest that is on a
/// node or on its way there is counted on that node at least once — as a
/// bound VM, as a reservation, or for the length of step 4 as both — and a
/// claim commits only if, at one revision at or after its own write, the
/// node's allowance covers the guests bound there plus every claim written
/// before it plus itself.
///
/// Why that is enough: take two claims X and Y on one node, X written first.
/// Y confirms at a revision after Y's own write and therefore after X's. At
/// that revision X is either still a reservation — counted ahead of Y — or
/// already a binding — counted as bound — because X's reservation is released
/// only after X's binding is written; it is never absent. So Y is measured
/// against X whichever way round the two replicas run, and whichever of the
/// two roads each is on. Nothing here can err toward an emptier node; the
/// one thing that errs toward a fuller one is step 4's overlap, and it costs
/// a slot for one round trip.
///
/// **A reservation outlives nothing.** It is taken away the moment its move
/// is over — a migration's on the migration's final state or the guest's
/// binding, a placement's the moment the binding is written — and if the
/// process that made it dies in between, the reaper on the reconcile tick
/// removes it: a migration's promise once its migration is final, deleted or
/// gone, a placement's once its guest is bound anywhere, gone, on its way
/// out, or the claim has stood longer than a placement can take
/// ([`STALE_PLACEMENT_AFTER_SECS`]). Reaping early is safe because of step
/// 3's guard — a binding whose claim was taken fails its compare-and-swap,
/// and the next pass claims again — so the reaper is allowed to be wrong in
/// the direction of "too soon", and is tuned to be wrong in the direction of
/// "a minute late". See [`orphaned_reservations`].
///
/// **What it costs.** One create and one guarded delete per placement, both
/// on this key; one node read and one two-range read per confirmation; and
/// the listing per tick that `hold` already made. In return, a replica's
/// placements are visible to every other replica's placements and migrations
/// at the moment they are claimed rather than at the moment they are bound —
/// which is the window Astra finding R3-F05 (2026-09-24) named: ordinary
/// placement booked capacity in a process-local mutex from a per-pass
/// snapshot and bound by CAS on the VM object alone, so two replicas each
/// succeeded against the same free capacity. Astra finding S07 (2026-09-23)
/// was the migration half of the same gap: nothing reserved a live
/// migration's destination between `prepare` and the guest's arrival.
///
/// This is an OBJECT and not a field on the node, for three reasons and each
/// of them is the reason a resource exists at all: several replicas share
/// nothing but their etcd, so the promise has to be in the store; a
/// create-only write on a key is the only way to make "exactly one claim for
/// this move" a fact rather than a convention; and a promise that has to be
/// reaped needs something to list. It is not a per-node ledger because a
/// ledger would be a second copy of a derived number, and a second copy in
/// etcd is a number that can be wrong — the argument `Candidate::free` makes
/// about itself.
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapacityReservationSpec {
    /// The machine the room is promised on.
    #[serde(default)]
    pub node: String,
    /// The guest it is promised to, by name — for the sentence a person
    /// reads, and for nothing a decision is made on.
    #[serde(default)]
    pub vm: String,
    /// Which guest it is. A name is what people call a VM and people reuse
    /// names; this is the identity, and it is what a destination's `Destroy`
    /// is addressed by, and what a placement's claim is named after.
    #[serde(default)]
    pub vm_uid: String,
    /// Which road the guest is on, and therefore which fact releases this.
    #[serde(default)]
    pub claimant: Claimant,
    /// The migration this promise belongs to, by name. Empty for a
    /// placement's claim.
    #[serde(default)]
    pub migration: String,
    /// And WHICH migration of that name. A migration is named for a vm and a
    /// moment, and a record can be removed and one made again under the same
    /// name; without this, releasing a reservation would be a delete by name
    /// alone — the ABA hole S19 closed for secrets, in a place where the cost
    /// of getting it wrong is a node carrying twice its memory.
    #[serde(default)]
    pub migration_uid: String,
    /// What the guest asks for, read by `Capacity::wanted_by` off the very
    /// spec the agent will be handed. Stored rather than looked up, because
    /// the whole point of this object is to be readable by a replica that
    /// cannot see the VM's future: a reservation whose size had to be derived
    /// from the VM would stop meaning anything the moment the VM was resized
    /// or removed mid-flight.
    #[serde(default)]
    pub vcpus: u32,
    #[serde(default)]
    pub mem_mib: u64,
}

impl CapacityReservationSpec {
    /// The promise, in the units a candidate's room is measured in.
    pub fn size(&self) -> crate::scheduler::Capacity {
        crate::scheduler::Capacity {
            vcpus: self.vcpus,
            mem_mib: self.mem_mib,
        }
    }
}

pub type CapacityReservation = Object<CapacityReservationSpec, ()>;

impl CapacityReservation {
    /// The reservation one migration would make at `node` for `vm`.
    ///
    /// One constructor, called by the one place that reserves, so the name
    /// and the uid pair can never be filled in two different ways — the whole
    /// of the release and the whole of the reaper are a comparison against
    /// what this wrote.
    pub fn of(migration: &VmMigration, vm: &Vm, node: &str) -> Self {
        let size = crate::scheduler::Capacity::wanted_by(vm);
        Self::declare(
            &migration.metadata.name,
            CapacityReservationSpec {
                node: node.to_string(),
                vm: vm.metadata.name.clone(),
                vm_uid: vm.metadata.uid.clone(),
                claimant: Claimant::Migration,
                migration: migration.metadata.name.clone(),
                migration_uid: migration.metadata.uid.clone(),
                vcpus: size.vcpus,
                mem_mib: size.mem_mib,
            },
        )
    }

    /// The claim one placement would make at `node` for `vm`.
    ///
    /// Named after the guest's UID and not its name, for the reason
    /// `migration_uid` exists: names are reused, and a claim standing for a
    /// VM that was deleted and made again under the same name must not be
    /// mistaken for the new one's. The uid is a lowercase UUID, which is a
    /// DNS label with a prefix on it, and no migration is named this way —
    /// so the two roads' claims cannot collide on a key.
    pub fn for_placement(vm: &Vm, node: &str) -> Self {
        let size = crate::scheduler::Capacity::wanted_by(vm);
        Self::declare(
            &format!("{PLACEMENT_CLAIM_PREFIX}{}", vm.metadata.uid),
            CapacityReservationSpec {
                node: node.to_string(),
                vm: vm.metadata.name.clone(),
                vm_uid: vm.metadata.uid.clone(),
                claimant: Claimant::Placement,
                migration: String::new(),
                migration_uid: String::new(),
                vcpus: size.vcpus,
                mem_mib: size.mem_mib,
            },
        )
    }

    /// Is this reservation the one `migration` made?
    ///
    /// Name AND uid, which is the whole point of carrying the uid: a record
    /// removed and made again under the same name is a different move, and a
    /// reservation held for the first of them is capacity nobody is coming
    /// for.
    pub fn belongs_to(&self, migration: &VmMigration) -> bool {
        self.spec.claimant == Claimant::Migration
            && self.spec.migration == migration.metadata.name
            && self.spec.migration_uid == migration.metadata.uid
    }

    /// Is this the claim a placement of `vm` made — this very VM, by uid?
    pub fn is_placement_of(&self, vm: &Vm) -> bool {
        self.spec.claimant == Claimant::Placement && self.spec.vm_uid == vm.metadata.uid
    }

    /// Is somebody still coming for this room, as far as `migrations` and
    /// `vms` can say at `now`?
    ///
    /// The two roads are released by two different facts, and this is where
    /// the field that tells them apart is read. A migration's promise is live
    /// while a migration of its own name and uid is still being carried; a
    /// placement's while its guest exists, is not on its way out, is bound
    /// nowhere, and the claim is younger than a placement can take. A claim
    /// with no creation time at all is read as ancient — the store stamps
    /// every object it makes, so one without a stamp is nothing this control
    /// plane wrote, and the safe reading of it is "nobody's".
    pub fn is_live(&self, migrations: &[VmMigration], vms: &[Vm], now: DateTime<Utc>) -> bool {
        match self.spec.claimant {
            Claimant::Migration => migrations.iter().any(|m| {
                self.belongs_to(m)
                    && m.metadata.deletion_timestamp.is_none()
                    && !m.status.phase().kind().is_final()
            }),
            Claimant::Placement => {
                let young = self.metadata.creation_timestamp.is_some_and(|made| {
                    now.signed_duration_since(made).num_seconds() <= STALE_PLACEMENT_AFTER_SECS
                });
                young
                    && vms.iter().any(|v| {
                        v.metadata.uid == self.spec.vm_uid
                            && v.metadata.deletion_timestamp.is_none()
                            && v.spec.node_name.is_none()
                    })
            }
        }
    }
}

/// The reservations nobody is coming for: the reaper's whole decision, as a
/// function that needs no store.
///
/// A reservation is live exactly while its move is still being carried — see
/// [`CapacityReservation::is_live`] for what that means on each road.
/// Everything else is an orphan. For a migration's promise the four ways to
/// become one are the four ways that comparison fails: the migration
/// finished, it failed, it was deleted, or its name was taken by a later
/// record. For a placement's claim there are four as well: the guest was
/// bound — here or anywhere, the binding is the count now — the guest is
/// gone, the guest is on its way out, or the claim has stood longer than a
/// placement can take and the process that wrote it is not coming back.
///
/// This is the invariant on the [`CapacityReservation`] type with a store
/// behind it: a reservation outlives nothing. A controller that died between
/// the claim and the binding — or between the reservation and the
/// migration's last phase — would otherwise hold a machine's room for ever,
/// and nothing in the fleet could say why the node was full.
///
/// `now` is passed in rather than read, so that the age rule can be tested
/// without waiting a minute.
pub fn orphaned_reservations<'a>(
    held: &'a [CapacityReservation],
    migrations: &[VmMigration],
    vms: &[Vm],
    now: DateTime<Utc>,
) -> Vec<&'a CapacityReservation> {
    held.iter()
        .filter(|r| !r.is_live(migrations, vms, now))
        .collect()
}

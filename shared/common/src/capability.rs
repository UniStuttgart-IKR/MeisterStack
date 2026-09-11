// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! How a node's device capability is spelled — in one place, for both sides
//! of the sentence.
//!
//! A node says what it can serve; a scheduler asks whether a candidate serves
//! what a VM wants. Both halves have to agree on one string format, and until
//! now each carried its own copy of it: the cluster session flattened
//! `DriverInfo` into `<driver>/<profile>` on its way into NodeCapacity, and
//! FirstFit built the same string again to compare against. Two spellings of
//! one convention, in two crates, with nothing between them but the tests
//! that happened to use the same examples.
//!
//! Neither half is device-specific — a driver name and an optional profile is
//! all this knows, and it is why the module is here rather than in
//! `controller-api`: the tier that BUILDS the catalogue and the tier that
//! MATCHES against it are different crates, and this is what they share.

/// The catalogue driver every STORAGE backend is a profile of: a node with
/// the LVM-thin driver claims `volume/lvm-thin`, and a VM whose spec names
/// that driver only fits where the claim is.
///
/// A prefix and not a bare `lvm-thin`, because this catalogue is one flat
/// list shared with the device half — a bare backend name in it would answer
/// a DEVICE request for a driver of that name, and the VM would bind to a
/// node that cannot serve it. Here rather than in either crate because both
/// halves of the sentence need it: the agent builds the entry, the scheduler
/// looks for it.
pub const VOLUME: &str = "volume";

/// The second segment a volume backend that can take point-in-time copies
/// claims: `volume/lvm-thin/snapshot` beside `volume/lvm-thin`.
///
/// Nested inside the profile rather than a driver of its own, and the reason
/// is that the catalogue is a flat list of `<driver>/<profile>` strings: the
/// claim has to say WHICH backend can do it, because a node may serve two and
/// disagree with itself (lvm-thin can, an nfs share cannot). `volume/snapshot`
/// would say only that something on this node can, which is not a question
/// anybody asks.
///
/// Here rather than in either crate for the reason `VOLUME` gives: the agent
/// builds the entry and the API edge looks for it.
pub const SNAPSHOT: &str = "snapshot";

/// The backend whose snapshot was atomic BY NAME, and the reason the name is
/// no longer how anybody should ask.
///
/// It used to be the whole mechanism: `SnapshotConsistency` was a driver's
/// answer and did not travel, so the tier deciding whether to pause a guest
/// read the pool's DRIVER and compared it with this string. The old comment
/// here named its own expiry date — "the day a second atomic backend arrives
/// this is a list, or the consistency starts travelling with the claim" — and
/// that day came from below: `filesystem` reflinks on XFS and btrfs, and it
/// finds that out by probing rather than by being told.
///
/// So the consistency travels now: see [`snapshot_claim`] and
/// [`parse_snapshot_claim`]. The constant stays because the driver's NAME is
/// still a name — it routes a pool to a backend — and because a reader that
/// still compares against it is wrong in the safe direction, quiescing a
/// backend that did not need it.
pub const LVM_THIN: &str = "lvm-thin";

/// What a backend has to be given for its snapshot to be worth anything.
///
/// Here rather than in `agent-api` for exactly the reason [`Locality`] is
/// here: the tier that STATES the fact is a driver and the tier that ACTS on
/// it is a controller, and no controller depends on `agent-api`.
/// `agent_api::storage` re-exports it, so a driver names it where a driver
/// lives.
///
/// Neither value promises a consistent GUEST. Both are crash-consistent —
/// what a snapshot holds is what the disk held at that instant, which is what
/// the guest would have found after losing power. There is no guest agent
/// here and no `fsfreeze`, exactly as EBS without one, and the difference the
/// two variants name is only whether the HOST needs the writes to stop while
/// it works.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SnapshotConsistency {
    /// The backend takes the snapshot at one instant on its own — a
    /// copy-on-write thin LV, a filesystem-level clone. Nothing has to be
    /// paused, so nothing is.
    Atomic,
    /// The backend copies, and a copy of a file being written to is a copy of
    /// no single moment. The tier above pauses the VM's vCPUs across the call
    /// and resumes them afterwards — see the cluster's snapshot sequence.
    NeedsQuiesce,
}

impl SnapshotConsistency {
    pub const ALL: [SnapshotConsistency; 2] = [
        SnapshotConsistency::Atomic,
        SnapshotConsistency::NeedsQuiesce,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            SnapshotConsistency::Atomic => "atomic",
            SnapshotConsistency::NeedsQuiesce => "needs-quiesce",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.as_str() == s)
    }
}

/// What separates a snapshot claim from the consistency written on it.
///
/// A colon and not another slash: the catalogue is split on `/` into
/// `<driver>/<profile>` by everything that reads it, and a third segment
/// would turn `volume/filesystem/snapshot` into an entry those splitters
/// count differently. Inside the profile, after a character `offers` never
/// looks at, the claim is invisible to every existing reader.
pub const CONSISTENCY_SEP: char = ':';

/// The profile a snapshotting backend claims, WITH what it needs:
/// `filesystem/snapshot:atomic`, flattening one tier up into
/// `volume/filesystem/snapshot:atomic`.
///
/// Claimed BESIDE the bare `<backend>/snapshot` and never instead of it. The
/// bare entry is what every reader built so far matches on, and a node that
/// stopped emitting it would have its pools refused by a cluster one release
/// older — the same mixed-version trap `HYPERVISOR` describes, and the same
/// answer: claiming is additive and safe, replacing is not.
pub fn snapshot_claim(backend: &str, consistency: SnapshotConsistency) -> String {
    format!(
        "{backend}/{SNAPSHOT}{CONSISTENCY_SEP}{}",
        consistency.as_str()
    )
}

/// The inverse, total: the backend and what its snapshot needs, out of one
/// catalogue profile.
///
/// `None` for the bare `<backend>/snapshot` as well as for anything that is
/// not a snapshot claim at all — a caller that gets `None` has learned
/// nothing and must fall back to quiescing, which is the direction where
/// being wrong costs milliseconds instead of a torn copy.
///
/// Takes the PROFILE (`filesystem/snapshot:atomic`) and not the flattened
/// catalogue entry, because that is what a `DriverInfo` carries and what the
/// tier above splits `volume/` off to get.
pub fn parse_snapshot_claim(profile: &str) -> Option<(&str, SnapshotConsistency)> {
    let (head, consistency) = profile.split_once(CONSISTENCY_SEP)?;
    let backend = head.strip_suffix(SNAPSHOT)?.strip_suffix('/')?;
    if backend.is_empty() {
        return None;
    }
    Some((backend, SnapshotConsistency::parse(consistency)?))
}

/// The catalogue driver every HYPERVISOR is a profile of: a node running the
/// cloud-hypervisor driver claims `hypervisor/cloud-hypervisor`.
///
/// New with the storage split, and it exists because a node stopped being
/// synonymous with "machine that runs VMs". A storage node has no hypervisor
/// at all, and without this entry it would look to a scheduler like an
/// ordinary candidate — the first VM asking for nothing in particular would
/// land there and fail at the first `create`.
///
/// The other half of the sentence — that every VM implicitly REQUESTS one —
/// shipped with storage A. It was held back for exactly as long as any node
/// in the fleet ran an agent that predates this entry: such a node claims no
/// `hypervisor/*`, and a VM that required one would go Pending on it forever.
/// Claiming is additive and safe on a mixed-version cluster; requiring is
/// not, and a rollout is the normal state. The last node still on a
/// hand-started binary from before the claim was replaced by the image round,
/// so the condition is met. See `scheduler::resource_requests`.
///
/// The request is BARE — any hypervisor answers it. Which one a node runs is
/// its own business, and matching the name would be sizing knowledge the
/// scheduler does not have.
pub const HYPERVISOR: &str = "hypervisor";

/// The catalogue driver every NETWORK capability is a profile of. A node
/// with a `[network.vxlan]` section claims `network/vxlan`, and a VM whose
/// spec puts a `vxlan_id` on any NIC only fits where that claim is.
///
/// Same prefix trick and same reason as `VOLUME`: one flat list is shared
/// with the device half, and a bare `vxlan` in it would answer a DEVICE
/// request for a driver of that name.
pub const NETWORK: &str = "network";
/// The one network capability there is so far. Named here rather than in the
/// driver because both halves of the sentence need the same string: the agent
/// builds the entry, the scheduler looks for it.
pub const VXLAN: &str = "vxlan";
/// The overlay's second flavour: the same VXLAN wire, with its MAC addresses
/// distributed by BGP instead of learned from flooded frames.
///
/// A second entry BESIDE `vxlan` and never instead of it — a node with EVPN on
/// still claims `network/vxlan`, because that is what a VM asks for and what
/// the scheduler matches. This entry is what `meister node ls` shows an
/// operator, and it exists for exactly that: EVPN is a cluster-wide decision
/// (two nodes of one overlay disagreeing about it never learn each other's
/// MACs), so an operator has to be able to SEE which nodes are on which side
/// of it. There is deliberately no scheduling request for it — a VM asks for
/// an overlay, not for how the overlay finds its peers.
pub const EVPN: &str = "evpn";

/// The network profile a node claims once per PROVIDER network it holds an
/// interface for: `gateway:ext` beside `vxlan`, flattening one tier up into
/// `network/gateway:ext`.
///
/// Decision 2 of 6k: **gateway is a capability out of the agent's config**,
/// not a separate agent and not a compile feature. A node with
/// `[network.provider] physnets = { ext = "eth1" }` builds the provider
/// bridge for `ext`, checks that the interface carries no address — the
/// interface was given away — and claims this. A node with no physnet claims
/// none and is no candidate for a router.
///
/// The physnet rides INSIDE the profile after a colon, exactly as a snapshot
/// backend's consistency does and for the same reason: the catalogue is split
/// on `/` into `<driver>/<profile>` by everything that reads it, and a third
/// slash would turn this into an entry those splitters count differently.
/// See [`CONSISTENCY_SEP`], which is the same character doing the same job.
///
/// Additive and safe on a mixed-version fleet, like every other claim here:
/// an agent that predates it claims nothing, and the routers simply do not go
/// there.
pub const GATEWAY: &str = "gateway";

/// What a gateway node claims for one physnet: `gateway:ext`.
pub fn gateway_claim(physnet: &str) -> String {
    format!("{GATEWAY}{CONSISTENCY_SEP}{physnet}")
}

/// The inverse, total: the physnet out of one catalogue PROFILE, or `None`
/// for a profile that is not a gateway claim at all.
///
/// Takes the profile (`gateway:ext`) rather than the flattened entry
/// (`network/gateway:ext`), for the reason [`parse_snapshot_claim`] does: a
/// `DriverInfo` carries the profile, and the tier above splits `network/` off
/// to get here.
pub fn parse_gateway_claim(profile: &str) -> Option<&str> {
    let (head, physnet) = profile.split_once(CONSISTENCY_SEP)?;
    (head == GATEWAY && !physnet.is_empty()).then_some(physnet)
}

/// Every provider network this catalogue says the node holds an interface
/// for, in the order it claimed them.
///
/// The scheduling question a router asks, and it is asked of a FLATTENED
/// catalogue (`NodeCapacity.capabilities`) because that is what a controller
/// has in hand — a `Candidate` never sees the `DriverInfo` list it was built
/// from.
pub fn gateway_physnets(catalogue: &[String]) -> Vec<&str> {
    catalogue
        .iter()
        .filter_map(|entry| entry.strip_prefix(&format!("{NETWORK}/")))
        .filter_map(parse_gateway_claim)
        .collect()
}

/// The storage backend a volume gets when its spec names none.
///
/// It is in this module for one reason, and the reason is a scheduling rule:
/// every node registers this backend whether or not it is configured, so a
/// volume that asks for it (by name or by saying nothing) constrains nothing
/// and must produce no request at all. Emitting one would strand such a VM on
/// any node whose agent predates the volume catalogue — it claims no
/// `volume/*` entries, and a VM with a plain disk would never be placed
/// there again. `agent_api::default_volume_driver` returns this string.
pub const DEFAULT_VOLUME_DRIVER: &str = "filesystem";

/// WHERE a volume backend's bytes are, from the point of view of the nodes
/// that can reach them.
///
/// A property of the DRIVER and never a setting on a pool. lvm-thin writes
/// into a volume group on one machine; the `filesystem` backend writes a file
/// into a directory on one machine; NFS hands every node that mounts the
/// export the same bytes. An admin who could call an lvm-thin pool `shared`
/// would be lying to the scheduler, and the VM placed on the strength of that
/// lie would come up on a node where the disk is not.
///
/// Here rather than in `agent-api` for the reason the rest of this module is
/// here: the tier that STATES the fact and the tier that ACTS on it are
/// different crates, and neither controller depends on `agent-api` (see
/// `VmSpec.vm`). `agent_api::storage` re-exports it, so a driver names it
/// where a driver lives.
///
/// The strings are the wire form: a `DriverInfo.locality` in the Hello, and
/// `StoragePool.status.locality` in the API. One spelling, three variants,
/// and a fourth would be a new variant here rather than a new convention
/// somewhere else.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    serde::Serialize,
    serde::Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum Locality {
    /// The bytes are on exactly one node and reachable from nowhere else.
    /// `filesystem` and `lvm-thin`. The default because it is the weakest
    /// claim: a backend nobody asked stays pinned to the node that made it,
    /// which is the safe direction to be wrong in.
    #[default]
    NodeLocal,
    /// Every node in the pool sees the SAME bytes at the same time. `nfs`.
    Shared,
    /// The bytes live somewhere else and reach a node over the network, one
    /// consumer at a time. No driver claims it yet — NVMe-oF does, and the
    /// value is here so the axis is complete before the driver arrives
    /// rather than after.
    Networked,
}

impl Locality {
    pub const ALL: [Locality; 3] = [Locality::NodeLocal, Locality::Shared, Locality::Networked];

    /// The wire spelling, and the only one. Both `DriverInfo.locality` and
    /// `StoragePool.status.locality` are this string.
    pub fn as_str(self) -> &'static str {
        match self {
            Locality::NodeLocal => "node-local",
            Locality::Shared => "shared",
            Locality::Networked => "networked",
        }
    }

    /// The inverse, total: `None` for anything that is not one of the three.
    ///
    /// An empty string is one of those, and it is the ordinary case rather
    /// than an error — a `DriverInfo` for a device driver carries no
    /// locality, and so does one from an agent that predates the field.
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|l| l.as_str() == s)
    }
}

/// One catalogue entry: `<driver>/<profile>`, or the bare driver name where a
/// driver resolves no profiles at all (vfio passthrough has nothing to
/// choose between).
pub fn entry(driver: &str, profile: Option<&str>) -> String {
    match profile {
        Some(p) => format!("{driver}/{p}"),
        None => driver.to_string(),
    }
}

/// Whether a catalogue serves a request.
///
/// A profiled request needs its exact entry — asking for `nvrm/4q` on a node
/// that only resolves `nvrm/2q` is not a fit, and pretending otherwise would
/// bind the VM somewhere it cannot start. A bare request is content with the
/// bare driver name or with any profile of it: "give me a vfio device" is
/// answered by a node offering vfio, and "give me an nvrm device" by a node
/// offering any nvrm profile, because the node picks in that case.
pub fn offers(catalogue: &[String], driver: &str, profile: Option<&str>) -> bool {
    match profile {
        Some(_) => {
            let want = entry(driver, profile);
            catalogue.contains(&want)
        }
        None => {
            let prefix = format!("{driver}/");
            catalogue
                .iter()
                .any(|have| have == driver || have.starts_with(&prefix))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_entry_is_the_driver_with_its_profile_or_the_driver_alone() {
        assert_eq!(entry("nvrm", Some("4q")), "nvrm/4q");
        assert_eq!(entry("vfio", None), "vfio");
    }

    /// The two spellings that used to live apart are now one round trip:
    /// whatever a node writes into its catalogue, a request for exactly that
    /// finds it.
    #[test]
    fn whatever_is_written_as_an_entry_is_found_by_the_matching_request() {
        for (driver, profile) in [
            ("nvrm", Some("4q")),
            ("crosvm-gpu", Some("venus")),
            ("vfio", None),
        ] {
            let catalogue = vec![entry(driver, profile)];
            assert!(offers(&catalogue, driver, profile), "{driver} {profile:?}");
            // and a bare request is answered by a profiled entry too
            assert!(offers(&catalogue, driver, None));
        }
    }

    #[test]
    fn a_profiled_request_needs_its_exact_entry() {
        let catalogue = vec![entry("nvrm", Some("2q")), entry("vfio", None)];
        assert!(offers(&catalogue, "nvrm", Some("2q")));
        assert!(
            !offers(&catalogue, "nvrm", Some("4q")),
            "wrong profile is not a fit"
        );
        assert!(
            !offers(&catalogue, "crosvm-gpu", Some("venus")),
            "wrong driver either"
        );
    }

    /// A bare request against a driver that resolves no profiles: the entry
    /// is the bare name, and the prefix rule must not be what answers it.
    #[test]
    fn a_bare_driver_answers_a_bare_request() {
        assert!(offers(&[entry("vfio", None)], "vfio", None));
        assert!(!offers(&[entry("vfio", None)], "vfio", Some("anything")));
    }

    /// The prefix is `driver/` and not `driver`: a node offering `nvrm-next`
    /// does not answer a request for `nvrm`. Cheap to get wrong with
    /// `starts_with(driver)`, and it would place a VM on a node that cannot
    /// start it.
    #[test]
    fn a_driver_name_that_merely_starts_the_same_is_not_a_match() {
        let catalogue = vec![entry("nvrm-next", Some("4q"))];
        assert!(!offers(&catalogue, "nvrm", None));
        assert!(!offers(&catalogue, "nvrm", Some("4q")));
        assert!(offers(&catalogue, "nvrm-next", Some("4q")));
    }

    /// Storage entries are ordinary profiled entries and go through the same
    /// two functions — which is the whole reason the `volume/` prefix was
    /// chosen over a second catalogue: nothing had to learn a new rule.
    #[test]
    fn a_storage_backend_is_a_profile_of_the_volume_driver() {
        let catalogue = vec![
            entry(VOLUME, Some(DEFAULT_VOLUME_DRIVER)),
            entry(VOLUME, Some("lvm-thin")),
        ];
        assert_eq!(catalogue[1], "volume/lvm-thin");
        assert!(offers(&catalogue, VOLUME, Some("lvm-thin")));
        assert!(!offers(&catalogue, VOLUME, Some("nfs")));
        // and a backend name never stands alone, so it cannot be mistaken
        // for a device driver of the same name
        assert!(!offers(&catalogue, "lvm-thin", None));
    }

    /// And the hypervisor half, through the same two functions again. Four
    /// kinds of capability now, one spelling — which is the whole reason
    /// there is no second catalogue: nothing had to learn a new rule to
    /// carry the entry that says a node runs VMs at all.
    #[test]
    fn a_hypervisor_is_a_profile_of_the_hypervisor_driver() {
        let catalogue = vec![entry(HYPERVISOR, Some("cloud-hypervisor"))];
        assert_eq!(catalogue[0], "hypervisor/cloud-hypervisor");
        assert!(offers(&catalogue, HYPERVISOR, Some("cloud-hypervisor")));
        assert!(
            offers(&catalogue, HYPERVISOR, None),
            "a bare request is answered by any hypervisor, because the node picks"
        );
        assert!(!offers(&catalogue, HYPERVISOR, Some("qemu")));
        // A storage node claims none of it, and answers neither request.
        assert!(!offers(&[], HYPERVISOR, None));
        // ... and never mistakable for a device driver of that name.
        assert!(!offers(&catalogue, "cloud-hypervisor", None));
    }

    /// The network half goes through the same two functions as the storage
    /// half and the device half — three kinds of capability, one spelling.
    #[test]
    fn an_overlay_is_a_profile_of_the_network_driver() {
        let catalogue = vec![entry(NETWORK, Some(VXLAN))];
        assert_eq!(catalogue[0], "network/vxlan");
        assert!(offers(&catalogue, NETWORK, Some(VXLAN)));
        assert!(!offers(&catalogue, NETWORK, Some("geneve")));
        // and never mistakable for a device driver called `vxlan`
        assert!(!offers(&catalogue, VXLAN, None));
    }

    /// The gateway half, through the same two functions once more — and the
    /// round trip is what the two baustellen of 6k agree on: the agent
    /// BUILDS the claim out of its `[network.provider]` section, the
    /// controller MATCHES a router's provider network against it, and
    /// neither writes the string itself.
    #[test]
    fn a_gateway_is_a_profile_of_the_network_driver_carrying_its_physnet() {
        let catalogue = vec![
            entry(NETWORK, Some(VXLAN)),
            entry(NETWORK, Some(&gateway_claim("ext"))),
            entry(NETWORK, Some(&gateway_claim("dmz"))),
        ];
        assert_eq!(catalogue[1], "network/gateway:ext");
        assert!(offers(&catalogue, NETWORK, Some("gateway:ext")));
        assert!(!offers(&catalogue, NETWORK, Some("gateway:public")));
        assert_eq!(gateway_physnets(&catalogue), vec!["ext", "dmz"]);
        // A node with no physnet claims none and is no candidate for a
        // router — which is the whole of decision 2's second half.
        assert!(gateway_physnets(&[entry(NETWORK, Some(VXLAN))]).is_empty());
        assert!(gateway_physnets(&[]).is_empty());
    }

    /// The claim parses only as itself. A physnet called `gateway` and a
    /// profile that merely starts the same way are both refused, because a
    /// wrong answer here places a tenant's way out on a machine that holds
    /// no interface for it.
    #[test]
    fn nothing_but_a_gateway_claim_parses_as_one() {
        assert_eq!(parse_gateway_claim("gateway:ext"), Some("ext"));
        assert_eq!(parse_gateway_claim("gateway:"), None);
        assert_eq!(parse_gateway_claim("gateway"), None);
        assert_eq!(parse_gateway_claim("gateways:ext"), None);
        assert_eq!(parse_gateway_claim("vxlan"), None);
        assert_eq!(parse_gateway_claim("filesystem/snapshot:atomic"), None);
        // And a gateway claim is not a snapshot claim, which is the other
        // reader of this separator.
        assert_eq!(parse_snapshot_claim("gateway:ext"), None);
    }

    /// EVPN is a second entry beside `vxlan`, never instead of it: a VM asks
    /// for an overlay and the scheduler matches `network/vxlan`, so a node
    /// that dropped that entry when it turned evpn on would stop being a
    /// candidate for the very VMs it serves best.
    #[test]
    fn an_evpn_node_still_answers_a_request_for_an_overlay() {
        let catalogue = vec![entry(NETWORK, Some(VXLAN)), entry(NETWORK, Some(EVPN))];
        assert_eq!(catalogue[1], "network/evpn");
        assert!(offers(&catalogue, NETWORK, Some(VXLAN)));
        assert!(offers(&catalogue, NETWORK, Some(EVPN)));
        // ... and a multicast node is not mistaken for an evpn one.
        assert!(!offers(&[entry(NETWORK, Some(VXLAN))], NETWORK, Some(EVPN)));
    }

    /// The gateway claim, both directions. The physnet is IN the profile
    /// because a router names the provider network it needs: a bare
    /// `gateway` would put a router on a node that gave away a different
    /// interface, in a different rack, to a different network.
    #[test]
    fn a_gateway_claim_names_the_provider_network_it_is_about() {
        let catalogue = vec![
            entry(NETWORK, Some(VXLAN)),
            entry(NETWORK, Some(&gateway_claim("ext"))),
        ];
        assert_eq!(catalogue[1], "network/gateway:ext");
        assert!(offers(&catalogue, NETWORK, Some("gateway:ext")));
        assert!(
            !offers(&catalogue, NETWORK, Some("gateway:dmz")),
            "another provider network is another node's business"
        );
        assert_eq!(parse_gateway_claim("gateway:ext"), Some("ext"));
        assert_eq!(parse_gateway_claim(&gateway_claim("dmz")), Some("dmz"));

        // Everything that is not one, and the empty name among them: a node
        // claiming `gateway:` has named no network and is a candidate for
        // nothing.
        assert_eq!(parse_gateway_claim("gateway:"), None);
        assert_eq!(parse_gateway_claim("gateway"), None);
        assert_eq!(parse_gateway_claim(VXLAN), None);
        assert_eq!(parse_gateway_claim("filesystem/snapshot:atomic"), None);
        // ... and a gateway claim is not mistakable for a snapshot one,
        // which is the one other user of this separator.
        assert_eq!(parse_snapshot_claim(&gateway_claim("ext")), None);
    }

    /// A node that gave an interface away still serves overlays, and the two
    /// claims are independent: a gateway node without `[network.vxlan]` can
    /// carry no tenant wire, and one with both is what a router needs.
    #[test]
    fn a_gateway_node_and_an_overlay_node_are_two_claims() {
        let gateway_only = vec![entry(NETWORK, Some(&gateway_claim("ext")))];
        assert!(!offers(&gateway_only, NETWORK, Some(VXLAN)));
        let both = vec![
            entry(NETWORK, Some(VXLAN)),
            entry(NETWORK, Some(&gateway_claim("ext"))),
        ];
        assert!(offers(&both, NETWORK, Some(VXLAN)));
        assert!(offers(&both, NETWORK, Some(&gateway_claim("ext"))));
    }

    /// The wire form is the only form, so whatever a driver says round-trips
    /// through the string a Hello carries and the API publishes. Without this
    /// the two ends would agree only by accident of spelling.
    #[test]
    fn a_locality_round_trips_through_its_wire_spelling() {
        for locality in Locality::ALL {
            assert_eq!(Locality::parse(locality.as_str()), Some(locality));
        }
        assert_eq!(Locality::NodeLocal.as_str(), "node-local");
        assert_eq!(Locality::Shared.as_str(), "shared");
        assert_eq!(Locality::Networked.as_str(), "networked");
    }

    /// The absent case is the ordinary one and must not be an error: a device
    /// driver's entry carries no locality, and neither does one from an agent
    /// that predates the field.
    #[test]
    fn nothing_that_is_not_one_of_the_three_parses() {
        assert_eq!(Locality::parse(""), None);
        assert_eq!(Locality::parse("nodelocal"), None);
        assert_eq!(Locality::parse("NodeLocal"), None);
    }

    /// serde spells it the same way `as_str` does, which is what lets the
    /// value stand in a published object and in a proto string without two
    /// conversions that could disagree.
    #[test]
    fn serde_spells_it_the_way_the_wire_does() {
        let json = serde_json::to_string(&Locality::NodeLocal).unwrap();
        assert_eq!(json, "\"node-local\"");
        assert_eq!(
            serde_json::from_str::<Locality>("\"shared\"").unwrap(),
            Locality::Shared
        );
    }

    #[test]
    fn an_empty_catalogue_serves_nothing() {
        assert!(!offers(&[], "vfio", None));
        assert!(!offers(&[], "nvrm", Some("4q")));
    }

    /// The claim round trip, both directions, and the compatibility rule that
    /// makes it safe to add.
    #[test]
    fn a_snapshot_claim_carries_its_consistency_without_hiding_the_bare_entry() {
        let atomic = snapshot_claim("filesystem", SnapshotConsistency::Atomic);
        assert_eq!(atomic, "filesystem/snapshot:atomic");
        assert_eq!(
            parse_snapshot_claim(&atomic),
            Some(("filesystem", SnapshotConsistency::Atomic))
        );
        assert_eq!(
            parse_snapshot_claim(&snapshot_claim("nfs", SnapshotConsistency::NeedsQuiesce)),
            Some(("nfs", SnapshotConsistency::NeedsQuiesce))
        );

        // The bare entry carries no answer. A reader that gets `None` has
        // learned nothing and must quiesce — the direction where being wrong
        // costs milliseconds rather than a torn copy.
        assert_eq!(parse_snapshot_claim("filesystem/snapshot"), None);
        assert_eq!(parse_snapshot_claim("nvrm/4q"), None);
        assert_eq!(parse_snapshot_claim("filesystem/snapshot:sometimes"), None);
        assert_eq!(parse_snapshot_claim("/snapshot:atomic"), None);
        assert_eq!(parse_snapshot_claim(""), None);

        // And the whole reason a colon was chosen over a third slash: the
        // catalogue a node publishes still answers the question every reader
        // built so far asks, because the two entries travel together.
        let catalogue = vec![
            entry(VOLUME, Some("filesystem/snapshot")),
            entry(VOLUME, Some(&atomic)),
        ];
        assert!(offers(&catalogue, VOLUME, Some("filesystem/snapshot")));
        assert!(offers(
            &catalogue,
            VOLUME,
            Some("filesystem/snapshot:atomic")
        ));
        assert!(!offers(&catalogue, VOLUME, Some("lvm-thin/snapshot")));
    }
}

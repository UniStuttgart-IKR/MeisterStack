// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Capability strings shared by agents, controllers and schedulers.
//!
//! Agents advertise driver/profile claims; placement and admission compare those
//! same claims. Storage claims use a `volume/` namespace to avoid colliding with
//! device names. Locality and snapshot consistency travel with backend claims.

/// Storage capability namespace, e.g. `volume/lvm-thin`. The prefix
/// keeps storage profiles distinct from device-driver profiles.
pub const VOLUME: &str = "volume";

/// Snapshot capability suffix, emitted beside the backend capability as
/// `volume/<backend>/snapshot`. Each backend advertises its own support.
pub const SNAPSHOT: &str = "snapshot";

/// LVM-thin driver name. Determine snapshot consistency from capability
/// claims, not from a backend-name comparison.
pub const LVM_THIN: &str = "lvm-thin";

/// Writer coordination required by a backend snapshot. Neither variant
/// provides application consistency or flushes guest buffers. Atomic captures
/// a storage instant; NeedsQuiesce requires host writes to stop during copying.
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

/// Separator between a snapshot profile and its consistency qualifier.
/// Keep `/` for the existing driver/profile structure.
pub const CONSISTENCY_SEP: char = ':';

/// Qualified snapshot profile, e.g. `filesystem/snapshot:atomic`. Emit
/// this in addition to the legacy `<backend>/snapshot` claim so older
/// controllers still recognize snapshot support.
pub fn snapshot_claim(backend: &str, consistency: SnapshotConsistency) -> String {
    format!(
        "{backend}/{SNAPSHOT}{CONSISTENCY_SEP}{}",
        consistency.as_str()
    )
}

/// Parse a qualified profile without its `volume/` prefix. Bare legacy
/// claims and malformed profiles return None; callers must conservatively
/// require quiescence when consistency is unknown.
pub fn parse_snapshot_claim(profile: &str) -> Option<(&str, SnapshotConsistency)> {
    let (head, consistency) = profile.split_once(CONSISTENCY_SEP)?;
    let backend = head.strip_suffix(SNAPSHOT)?.strip_suffix('/')?;
    if backend.is_empty() {
        return None;
    }
    Some((backend, SnapshotConsistency::parse(consistency)?))
}

/// Hypervisor capability namespace, for example `hypervisor/cloud-hypervisor`.
/// Every VM implicitly requests a bare hypervisor capability, so storage-only
/// nodes cannot receive VMs. An agent omitting the claim is not VM-eligible.
pub const HYPERVISOR: &str = "hypervisor";

/// Network capability namespace, e.g. `network/vxlan`, distinct from
/// device-driver profiles in the shared catalogue.
pub const NETWORK: &str = "network";
/// The one network capability there is so far. Named here rather than in the
/// driver because both halves of the sentence need the same string: the agent
/// builds the entry, the scheduler looks for it.
pub const VXLAN: &str = "vxlan";
/// EVPN capability, emitted alongside VXLAN for operator visibility.
/// Scheduling still requests VXLAN. All participating overlay nodes need
/// compatible discovery/routing configuration.
pub const EVPN: &str = "evpn";

/// Gateway profile for one configured provider network, such as `gateway:ext`
/// and the flattened capability `network/gateway:ext`. The colon keeps the
/// physnet inside the profile; `/` remains the driver/profile separator.
/// Nodes without this claim cannot host a router on that provider network.
pub const GATEWAY: &str = "gateway";

/// What a gateway node claims for one physnet: `gateway:ext`.
pub fn gateway_claim(physnet: &str) -> String {
    format!("{GATEWAY}{CONSISTENCY_SEP}{physnet}")
}

/// Parse a gateway profile such as `gateway:ext`, without the flattened
/// `network/` prefix. Return None for other profile shapes.
pub fn parse_gateway_claim(profile: &str) -> Option<&str> {
    let (head, physnet) = profile.split_once(CONSISTENCY_SEP)?;
    (head == GATEWAY && !physnet.is_empty()).then_some(physnet)
}

/// Read provider physnets from flattened capability entries, preserving
/// advertisement order.
pub fn gateway_physnets(catalogue: &[String]) -> Vec<&str> {
    catalogue
        .iter()
        .filter_map(|entry| entry.strip_prefix(&format!("{NETWORK}/")))
        .filter_map(parse_gateway_claim)
        .collect()
}

/// Default storage backend. Requests for this implicit backend do not
/// require a catalogue entry, preserving placement on older agents that
/// provide filesystem storage without advertising volume profiles.
pub const DEFAULT_VOLUME_DRIVER: &str = "filesystem";

/// Backend locality shared by agents and schedulers. It is reported by the
/// driver, not configured on a pool: local bytes require their node, shared
/// bytes require access to the same backend, and networked bytes are reached
/// through a remote target. Strings are used by Hello and pool status.
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
    /// Data accessible only on its owning node, as for filesystem and
    /// LVM-thin. The default avoids assuming remote accessibility.
    #[default]
    NodeLocal,
    /// Every node in the pool sees the SAME bytes at the same time. `nfs`.
    Shared,
    /// Remote data reached over the network by one consumer at a time,
    /// as with NVMe-oF.
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

    /// Parse known locality names. Empty or unknown strings return None,
    /// including device reports and legacy agents without locality metadata.
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

/// Match an exact profile, or for a bare request accept the driver name
/// or any of its profiles. A different profile never satisfies a named request.
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

    /// Driver-prefix matching requires the slash boundary; nvrm-next is not nvrm.
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

    /// Hypervisor capabilities use the common catalogue matching rules.
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

    /// Gateway construction and matching share one physnet claim format.
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

    /// Reject bare or partial gateway claim names.
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

    /// EVPN advertisement retains VXLAN, which VM scheduling requires.
    #[test]
    fn an_evpn_node_still_answers_a_request_for_an_overlay() {
        let catalogue = vec![entry(NETWORK, Some(VXLAN)), entry(NETWORK, Some(EVPN))];
        assert_eq!(catalogue[1], "network/evpn");
        assert!(offers(&catalogue, NETWORK, Some(VXLAN)));
        assert!(offers(&catalogue, NETWORK, Some(EVPN)));
        // ... and a multicast node is not mistaken for an evpn one.
        assert!(!offers(&[entry(NETWORK, Some(VXLAN))], NETWORK, Some(EVPN)));
    }

    /// Gateway claims round-trip the exact provider physnet.
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

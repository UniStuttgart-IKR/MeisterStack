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
/// is deliberately NOT built yet. It may only ship once no node in the
/// cluster runs an agent that predates this entry: such a node claims no
/// `hypervisor/*`, and a VM that required one would go Pending on it
/// forever. Claiming is additive and safe on a mixed-version cluster;
/// requiring is not, and a rollout is the normal state.
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
/// the scheduler matches. This entry is what `meister cluster nodes` shows an
/// operator, and it exists for exactly that: EVPN is a cluster-wide decision
/// (two nodes of one overlay disagreeing about it never learn each other's
/// MACs), so an operator has to be able to SEE which nodes are on which side
/// of it. There is deliberately no scheduling request for it — a VM asks for
/// an overlay, not for how the overlay finds its peers.
pub const EVPN: &str = "evpn";

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

    #[test]
    fn an_empty_catalogue_serves_nothing() {
        assert!(!offers(&[], "vfio", None));
        assert!(!offers(&[], "nvrm", Some("4q")));
    }
}

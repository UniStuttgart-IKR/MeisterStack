// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Scheduling as a plugin trait: v1 ships best-effort First-Fit; smarter
//! strategies (distributed best effort, bin packing, GPU-topology aware)
//! replace the implementation, not the reconciler.
//!
//! One trait serves both tiers. A cluster picks a node for a VM, the cloud
//! picks a cluster for a VM, and the decision is the same shape both times —
//! so the candidate is named for what it is to the scheduler, not for which
//! tier it happens to live on.

use macros::generated;

use common::capability::{self, offers};
use tracing::debug;

use crate::resources::Vm;

/// What the scheduler knows about a placement candidate, assembled from the
/// Node (or Cluster) objects in etcd rather than from the session map alone.
#[derive(Clone, Debug)]
pub struct Candidate {
    pub name: String,
    /// A session exists AND the candidate's heartbeat has not expired.
    pub connected: bool,
    /// `spec.schedulable` — an operator draining it without stopping it.
    pub schedulable: bool,
    /// The candidate's device catalogue, spelled by `common::capability`
    /// — the same function the node's own capacity is built with, so the two
    /// halves of the sentence cannot drift apart. Empty = no devices offered.
    ///
    /// Named for what it holds rather than for the field it is read from:
    /// `NodeCapacity.capabilities` is a wire name (design §2, control.proto)
    /// and stays, but nothing in the scheduler is about GPUs.
    pub catalogue: Vec<String>,
}

pub trait Scheduler: Send + Sync {
    /// Pick a placement for an unbound VM; None = leave it Pending.
    fn assign(&self, vm: &Vm, candidates: &[Candidate]) -> Option<String>;
}

/// The TOML spelling: `scheduler = "first-fit"`.
///
/// The same shape `retry` has for the requeue policy, and for the same
/// reason: a plugin trait with exactly one implementation wired in by hand is
/// not a seam, it is a comment about one. Both controllers resolve their
/// scheduler through here, so a second strategy is a new arm and a new line in
/// a config file rather than an edit in two `main`s.
#[derive(Debug, Clone, serde::Deserialize)]
#[generated(model = ClaudeOpus, version = "5")]
pub struct SchedulerConfig(pub String);

#[generated(model = ClaudeOpus, version = "5")]
impl SchedulerConfig {
    /// Default when the config says nothing: First-Fit — what both tiers were
    /// wired to outright before this was a choice, so a config that does not
    /// mention a scheduler still gets exactly the placement it had.
    pub fn into_scheduler(this: Option<Self>) -> anyhow::Result<std::sync::Arc<dyn Scheduler>> {
        Ok(match this.as_ref().map(|s| s.0.as_str()) {
            None | Some("first-fit") => std::sync::Arc::new(FirstFit),
            Some(other) => {
                anyhow::bail!("scheduler = {other:?}, expected \"first-fit\"")
            }
        })
    }
}

/// What the VM's opaque spec demands of a candidate's catalogue.
///
/// The controller deliberately does not parse the whole NewVmSpec — the
/// agent's serde stays the validator — but the driver names in it are the one
/// part scheduling cannot be correct without. Two lists now, one shape:
/// `devices[].driver`/`.profile` as they always were, and `volumes[].driver`
/// as a profile of the `volume` capability, because that is how a node claims
/// a storage backend (see `common::capability::VOLUME`). Without the second
/// half, an lvm-thin VM lands wherever there is room and fails at the first
/// `lvcreate`.
///
/// A volume that names no driver — or names the default one — produces no
/// request at all. It genuinely constrains nothing: every node registers that
/// backend whether or not it is configured. And asking for it anyway would
/// strand such a VM on any node whose agent predates the volume catalogue,
/// which claims no `volume/*` entries and would then never take a plain disk
/// again. A mixed-version cluster is the normal state during a rollout, and
/// that is the case this rule is for.
///
/// Three lists now: `nics[].vxlan_id` is the third, as a profile of the
/// `network` capability. The same argument one more time and a sharper one —
/// an overlay VM on a node with no `[network.vxlan]` section does not merely
/// fail late; the agent there refuses it outright, and the only alternative to
/// refusing would be a tenant's VM on the shared default bridge. A NIC that
/// names no overlay asks for nothing, so a plain VM still lands on any node,
/// including one whose agent predates all of this.
#[generated(model = ClaudeFable, version = "5")]
fn resource_requests(vm: &Vm) -> Vec<(String, Option<String>)> {
    let array = |field: &str| -> &[serde_json::Value] {
        vm.spec
            .vm
            .get(field)
            .and_then(|d| d.as_array())
            .map(Vec::as_slice)
            .unwrap_or(&[])
    };

    let mut requests: Vec<(String, Option<String>)> = array("devices")
        .iter()
        .filter_map(|d| {
            let driver = d.get("driver")?.as_str()?.to_string();
            let profile = d
                .get("profile")
                .and_then(|p| p.as_str())
                .map(str::to_string);
            Some((driver, profile))
        })
        .collect();

    requests.extend(array("volumes").iter().filter_map(|v| {
        let driver = v.get("driver").and_then(|d| d.as_str())?;
        (driver != capability::DEFAULT_VOLUME_DRIVER)
            .then(|| (capability::VOLUME.to_string(), Some(driver.to_string())))
    }));

    // One request however many NICs are on the overlay: what is being asked
    // for is a node that can join overlays at all, and asking for it twice
    // would only make the debug line longer.
    if array("nics")
        .iter()
        .any(|n| n.get("vxlan_id").is_some_and(|v| !v.is_null()))
    {
        requests.push((
            capability::NETWORK.to_string(),
            Some(capability::VXLAN.to_string()),
        ));
    }

    requests
}

/// What one VM asks of the machine it lands on, derived from its spec once
/// and then asked as often as a scheduler likes.
///
/// A seam, not a new rule — the derivation below is `resource_requests`
/// unchanged. It exists so that the next scheduler can ASK what a VM needs
/// instead of re-reading `spec.vm` to find out: the placement contract of a
/// volume driver or a vxlan nic is a property of the spec, not of whichever
/// strategy is looking at it, and two strategies deriving it separately is how
/// they start disagreeing about where an lvm-thin VM may run.
#[generated(model = ClaudeOpus, version = "5")]
pub struct DevicePolicy(Vec<(String, Option<String>)>);

#[generated(model = ClaudeOpus, version = "5")]
impl DevicePolicy {
    pub fn of(vm: &Vm) -> Self {
        Self(resource_requests(vm))
    }

    /// A VM that constrains nothing places anywhere.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Does this candidate's catalogue offer everything the VM asked for?
    /// Every request on ONE candidate: a combo VM cannot be split across two.
    pub fn met_by(&self, catalogue: &[String]) -> bool {
        self.0
            .iter()
            .all(|(driver, profile)| offers(catalogue, driver, profile.as_deref()))
    }

    /// The requests themselves, for a scheduler that wants to say what it
    /// could not place.
    pub fn requests(&self) -> &[(String, Option<String>)] {
        &self.0
    }

    /// The requests no usable candidate offers, spelled the way a catalogue
    /// spells them (`nvrm/4q`, `volume/lvm-thin`, `network/vxlan`).
    ///
    /// Not "which candidate fell short" but "what nobody has": a VM needs ALL
    /// of its requests on ONE candidate, so the useful answer to an operator
    /// is the part of the ask that no single machine can serve.
    #[generated(model = ClaudeFable, version = "5")]
    pub fn unmet(&self, candidates: &[Candidate]) -> Vec<String> {
        let usable: Vec<&Candidate> = candidates
            .iter()
            .filter(|c| c.connected && c.schedulable)
            .collect();
        self.0
            .iter()
            .filter(|(driver, profile)| {
                !usable
                    .iter()
                    .any(|c| offers(&c.catalogue, driver, profile.as_deref()))
            })
            .map(|(driver, profile)| capability::entry(driver, profile.as_deref()))
            .collect()
    }
}

/// Why a VM found no placement, in one sentence an operator can act on.
///
/// The scheduler's `None` is the whole of what the reconciler learns, and
/// until now the explanation existed only as a `debug!` line inside a
/// controller — so a Pending VM was a dead end for anybody holding only the
/// API. This turns the same three cases into a sentence that can be stored on
/// the object and read back with `vm inspect`.
///
/// The order matters: "nobody is here" and "nobody is willing" are different
/// operator problems from "nobody can", and only the third one is about the
/// VM's own demands.
#[generated(model = ClaudeFable, version = "5")]
pub fn pending_reason(vm: &Vm, candidates: &[Candidate]) -> String {
    if candidates.is_empty() {
        return "no candidates are known here yet".to_string();
    }
    let usable = candidates
        .iter()
        .filter(|c| c.connected && c.schedulable)
        .count();
    if usable == 0 {
        return format!(
            "none of the {} known candidates is both connected and schedulable",
            candidates.len()
        );
    }
    let wanted = DevicePolicy::of(vm);
    let unmet = wanted.unmet(candidates);
    if unmet.is_empty() {
        // Every request IS served somewhere, so the ask is servable in
        // principle and the split is what defeated it: no single candidate
        // holds the whole set. Worth its own sentence, because the operator
        // fix is different (put the capabilities on one machine, or ask for
        // less on one vm).
        return format!(
            "no single candidate offers all of [{}] at once, though each part is served somewhere",
            wanted
                .requests()
                .iter()
                .map(|(d, p)| capability::entry(d, p.as_deref()))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    format!("no connected candidate offers [{}]", unmet.join(", "))
}

#[generated(model = ClaudeFable, version = "5")]
pub struct FirstFit;

#[generated(model = ClaudeFable, version = "5")]
impl Scheduler for FirstFit {
    fn assign(&self, vm: &Vm, candidates: &[Candidate]) -> Option<String> {
        let wanted = DevicePolicy::of(vm);
        let placed = candidates
            .iter()
            .filter(|c| c.connected && c.schedulable)
            .find(|c| wanted.met_by(&c.catalogue))
            .map(|c| c.name.clone());
        // The "clear message" for a request nobody serves: candidates were up
        // and willing, the catalogue is what said no.
        if placed.is_none()
            && !wanted.is_empty()
            && candidates.iter().any(|c| c.connected && c.schedulable)
        {
            debug!(vm = %vm.metadata.name, requests = ?wanted.requests(),
                   "no candidate offers everything this vm asks for");
        }
        placed
    }
}

#[cfg(test)]
#[generated(model = ClaudeOpus, version = "5")]
mod tests {
    use super::*;
    use crate::resources::{VmSpec, new_vm};

    fn candidate(name: &str, connected: bool, schedulable: bool) -> Candidate {
        Candidate {
            name: name.into(),
            connected,
            schedulable,
            catalogue: Vec::new(),
        }
    }

    fn gpu_candidate(name: &str, profiles: &[&str]) -> Candidate {
        Candidate {
            name: name.into(),
            connected: true,
            schedulable: true,
            catalogue: profiles.iter().map(|p| p.to_string()).collect(),
        }
    }

    fn vm() -> Vm {
        vm_asking(serde_json::json!({}))
    }

    fn vm_asking(spec: serde_json::Value) -> Vm {
        new_vm(
            "t",
            VmSpec {
                node_name: None,
                cluster_name: None,
                run_strategy: Default::default(),
                tenant: None,
                vm: spec,
            },
        )
    }

    #[test]
    fn first_fit_skips_candidates_that_are_down_or_drained() {
        let candidates = [
            candidate("gone", false, true),
            candidate("draining", true, false),
            candidate("ok", true, true),
        ];
        assert_eq!(FirstFit.assign(&vm(), &candidates).as_deref(), Some("ok"));
    }

    #[test]
    fn no_usable_candidate_leaves_the_vm_pending() {
        assert_eq!(
            FirstFit.assign(&vm(), &[candidate("gone", false, true)]),
            None
        );
    }

    /// The same FirstFit decides both tiers; nothing in it knows whether the
    /// names it is choosing between are nodes or whole clusters.
    #[test]
    fn the_same_scheduler_places_on_clusters() {
        let clusters = [
            candidate("cluster-1", false, true),
            candidate("cluster-2", true, true),
        ];
        assert_eq!(
            FirstFit.assign(&vm(), &clusters).as_deref(),
            Some("cluster-2")
        );
    }

    fn nvrm_4q() -> serde_json::Value {
        serde_json::json!({"devices": [{"driver": "nvrm", "partition": "mediated", "profile": "4q"}]})
    }

    /// The testenv matrix's GPU pinning: a profiled device request must land
    /// on the one candidate whose catalogue carries it, however early a
    /// device-less candidate sits in the list.
    #[test]
    fn a_device_request_skips_candidates_that_do_not_offer_it() {
        let candidates = [
            gpu_candidate("agent-1a", &[]),
            gpu_candidate(
                "manacor",
                &["nvrm/2q", "nvrm/4q", "crosvm-gpu/venus", "vfio"],
            ),
        ];
        assert_eq!(
            FirstFit
                .assign(&vm_asking(nvrm_4q()), &candidates)
                .as_deref(),
            Some("manacor")
        );
        // and a VM without device requests still takes the first fit
        assert_eq!(
            FirstFit.assign(&vm(), &candidates).as_deref(),
            Some("agent-1a")
        );
    }

    /// The negative half of the matrix: a cluster with no GPU node leaves the
    /// VM Pending rather than binding it somewhere it cannot start.
    #[test]
    fn an_unserved_device_request_stays_pending() {
        let candidates = [
            gpu_candidate("agent-2a", &[]),
            gpu_candidate("agent-2b", &[]),
        ];
        assert_eq!(FirstFit.assign(&vm_asking(nvrm_4q()), &candidates), None);
    }

    /// vfio resolves no profiles, so its capacity entry is the bare driver
    /// name — and a bare request is content with any profile of its driver.
    /// The rule itself lives in `common::capability` and is tested there;
    /// what this holds is that FirstFit asks it the right question.
    #[test]
    fn bare_and_profiled_requests_match_the_catalogue_spellings() {
        let bare_vfio = serde_json::json!({"devices": [{"driver": "vfio"}]});
        let bare_nvrm = serde_json::json!({"devices": [{"driver": "nvrm"}]});
        let candidates = [gpu_candidate("manacor", &["nvrm/4q", "vfio"])];
        assert_eq!(
            FirstFit
                .assign(&vm_asking(bare_vfio), &candidates)
                .as_deref(),
            Some("manacor")
        );
        assert_eq!(
            FirstFit
                .assign(&vm_asking(bare_nvrm), &candidates)
                .as_deref(),
            Some("manacor")
        );
        // profiled request, wrong profile: no fit
        let nvrm_8q = serde_json::json!({"devices": [{"driver": "nvrm", "profile": "8q"}]});
        assert_eq!(FirstFit.assign(&vm_asking(nvrm_8q), &candidates), None);
    }

    fn volume_candidate(name: &str, backends: &[&str]) -> Candidate {
        Candidate {
            name: name.into(),
            connected: true,
            schedulable: true,
            catalogue: backends
                .iter()
                .map(|b| capability::entry(capability::VOLUME, Some(b)))
                .collect(),
        }
    }

    fn vm_with_volumes(volumes: serde_json::Value) -> Vm {
        vm_asking(serde_json::json!({ "volumes": volumes }))
    }

    /// The half this pass added, as a table. A spec's `volumes[].driver` is a
    /// placement constraint exactly as `devices[].driver` is: an lvm-thin VM
    /// on a node without the backend would fail at the first `lvcreate`,
    /// after being bound and started.
    #[test]
    fn a_volume_driver_places_the_vm_the_same_way_a_device_driver_does() {
        let plain = volume_candidate("agent-1a", &["filesystem"]);
        let thin = volume_candidate("manacor", &["filesystem", "lvm-thin", "nfs"]);

        for (name, volumes, expected) in [
            // no driver named: the default, which every node has
            (
                "default",
                serde_json::json!([{"size_bytes": 1}]),
                Some("agent-1a"),
            ),
            // named explicitly: still the default, still everywhere
            (
                "default by name",
                serde_json::json!([{"size_bytes": 1, "driver": "filesystem"}]),
                Some("agent-1a"),
            ),
            // a real backend: only where it is configured
            (
                "lvm-thin",
                serde_json::json!([{"size_bytes": 1, "driver": "lvm-thin"}]),
                Some("manacor"),
            ),
            (
                "nfs",
                serde_json::json!([{"size_bytes": 1, "driver": "nfs"}]),
                Some("manacor"),
            ),
            // nobody serves it: Pending, rather than bound where it dies
            (
                "ceph",
                serde_json::json!([{"size_bytes": 1, "driver": "ceph"}]),
                None,
            ),
            // a boot disk anywhere plus a share only manacor can serve
            (
                "mixed",
                serde_json::json!([
                    {"size_bytes": 1},
                    {"size_bytes": 0, "driver": "nfs", "params": {"kind": "share"}},
                ]),
                Some("manacor"),
            ),
        ] {
            let candidates = [plain.clone(), thin.clone()];
            assert_eq!(
                FirstFit
                    .assign(&vm_with_volumes(volumes), &candidates)
                    .as_deref(),
                expected,
                "{name}"
            );
        }
    }

    /// The rollout case, and the reason the default driver produces no
    /// request: a node running an agent from before the volume catalogue
    /// claims no `volume/*` entries at all. A VM with a plain disk still
    /// belongs there — it always did.
    #[test]
    fn a_plain_disk_still_places_on_a_node_that_claims_no_storage_at_all() {
        let old = [gpu_candidate("agent-1a", &[])];
        let plain = serde_json::json!([{"size_bytes": 1}]);
        assert_eq!(
            FirstFit.assign(&vm_with_volumes(plain), &old).as_deref(),
            Some("agent-1a")
        );
        // but a backend it never claimed is still refused
        let thin = serde_json::json!([{"size_bytes": 1, "driver": "lvm-thin"}]);
        assert_eq!(FirstFit.assign(&vm_with_volumes(thin), &old), None);
    }

    fn overlay_candidate(name: &str, vxlan: bool) -> Candidate {
        Candidate {
            name: name.into(),
            connected: true,
            schedulable: true,
            catalogue: if vxlan {
                vec![capability::entry(
                    capability::NETWORK,
                    Some(capability::VXLAN),
                )]
            } else {
                Vec::new()
            },
        }
    }

    fn vm_with_nics(nics: serde_json::Value) -> Vm {
        vm_asking(serde_json::json!({ "nics": nics }))
    }

    /// The third list, as a table. A tenant VM must never land on a node
    /// without an overlay: there the agent refuses it, and the only
    /// alternative to refusing would be the VM on the shared default bridge —
    /// which is the one outcome tenancy exists to prevent.
    #[test]
    fn a_vxlan_nic_places_the_vm_only_where_overlays_are_served() {
        let plain = overlay_candidate("agent-1a", false);
        let overlay = overlay_candidate("agent-1b", true);

        for (name, nics, expected) in [
            // no overlay named: any node, including one that serves none
            ("plain nic", serde_json::json!([{}]), Some("agent-1a")),
            ("no nics at all", serde_json::json!([]), Some("agent-1a")),
            // an explicit null is "none named", not "named nothing"
            (
                "null vxlan_id",
                serde_json::json!([{"vxlan_id": null}]),
                Some("agent-1a"),
            ),
            // a tenant nic: only where the section is configured
            (
                "tenant nic",
                serde_json::json!([{"vxlan_id": 10000}]),
                Some("agent-1b"),
            ),
            // one plain, one on the overlay: the node has to serve both
            (
                "mixed",
                serde_json::json!([{}, {"vxlan_id": 10000}]),
                Some("agent-1b"),
            ),
        ] {
            let candidates = [plain.clone(), overlay.clone()];
            assert_eq!(
                FirstFit.assign(&vm_with_nics(nics), &candidates).as_deref(),
                expected,
                "{name}"
            );
        }
    }

    /// The negative half: a cluster where nobody serves overlays leaves the
    /// tenant VM Pending rather than binding it where it cannot start.
    #[test]
    fn an_overlay_vm_with_nowhere_to_go_stays_pending() {
        let none = [overlay_candidate("a", false), overlay_candidate("b", false)];
        let tenant = serde_json::json!([{"vxlan_id": 10000}]);
        assert_eq!(FirstFit.assign(&vm_with_nics(tenant), &none), None);
        // while a plain VM is placed on exactly the same cluster
        assert_eq!(
            FirstFit
                .assign(&vm_with_nics(serde_json::json!([{}])), &none)
                .as_deref(),
            Some("a")
        );
    }

    /// Two NICs on the overlay ask for one thing, not two. Nothing depends on
    /// the count, and a duplicate would only make the "nobody serves this"
    /// debug line say it twice.
    #[test]
    fn several_overlay_nics_are_still_one_request() {
        let both = [overlay_candidate("agent-1b", true)];
        let two = serde_json::json!([{"vxlan_id": 10000}, {"vxlan_id": 10000}]);
        assert_eq!(
            FirstFit.assign(&vm_with_nics(two), &both).as_deref(),
            Some("agent-1b")
        );
    }

    /// Devices and volumes are one requirement list: a GPU VM on thin
    /// provisioning needs a node with both, and there is no splitting it.
    #[test]
    fn a_device_and_a_volume_request_must_meet_on_the_same_candidate() {
        let spec = serde_json::json!({
            "devices": [{"driver": "nvrm", "profile": "4q"}],
            "volumes": [{"size_bytes": 1, "driver": "lvm-thin"}],
        });
        let gpu_only = [gpu_candidate("gpu", &["nvrm/4q"])];
        let storage_only = [gpu_candidate("thin", &["volume/lvm-thin"])];
        let both = [gpu_candidate("manacor", &["nvrm/4q", "volume/lvm-thin"])];
        assert_eq!(FirstFit.assign(&vm_asking(spec.clone()), &gpu_only), None);
        assert_eq!(
            FirstFit.assign(&vm_asking(spec.clone()), &storage_only),
            None
        );
        assert_eq!(
            FirstFit.assign(&vm_asking(spec), &both).as_deref(),
            Some("manacor")
        );
    }

    /// All three kinds on one candidate: the overlay is not a special case,
    /// it is a third entry in the same list, matched by the same rule.
    #[test]
    fn a_device_a_volume_and_an_overlay_must_all_meet_on_one_candidate() {
        let spec = serde_json::json!({
            "devices": [{"driver": "nvrm", "profile": "4q"}],
            "volumes": [{"size_bytes": 1, "driver": "lvm-thin"}],
            "nics": [{"vxlan_id": 10000}],
        });
        let no_overlay = [gpu_candidate("half", &["nvrm/4q", "volume/lvm-thin"])];
        assert_eq!(FirstFit.assign(&vm_asking(spec.clone()), &no_overlay), None);
        let all = [gpu_candidate(
            "manacor",
            &["nvrm/4q", "volume/lvm-thin", "network/vxlan"],
        )];
        assert_eq!(
            FirstFit.assign(&vm_asking(spec), &all).as_deref(),
            Some("manacor")
        );
    }

    /// The seam itself: what a scheduler asks a spec for is a list of
    /// (driver, profile) pairs, and asking is all a second strategy has to do
    /// to place a VM the way this one would.
    #[test]
    fn a_spec_states_its_requirements_once_for_every_scheduler_to_read() {
        let spec = serde_json::json!({
            "devices": [{"driver": "nvrm", "profile": "4q"}],
            "volumes": [{"size_bytes": 1, "driver": "lvm-thin"}],
            "nics": [{"vxlan_id": 10000}],
        });
        let wanted = DevicePolicy::of(&vm_asking(spec));
        assert_eq!(
            wanted.requests(),
            [
                ("nvrm".to_string(), Some("4q".to_string())),
                ("volume".to_string(), Some("lvm-thin".to_string())),
                ("network".to_string(), Some("vxlan".to_string())),
            ]
        );
        assert!(wanted.met_by(&[
            "nvrm/4q".into(),
            "volume/lvm-thin".into(),
            "network/vxlan".into()
        ]));
        assert!(!wanted.met_by(&["nvrm/4q".into()]));
        // and a spec that constrains nothing is met by a candidate that
        // claims nothing
        assert!(DevicePolicy::of(&vm()).is_empty());
        assert!(DevicePolicy::of(&vm()).met_by(&[]));
    }

    /// The config seam: nothing configured is the FirstFit both controllers
    /// were wired to by hand, and a name nobody serves is an error at
    /// start-up rather than a silently different placement.
    #[test]
    fn the_scheduler_spelling_resolves() {
        #[derive(serde::Deserialize)]
        struct F {
            scheduler: Option<SchedulerConfig>,
        }
        let parse = |s: &str| toml::from_str::<F>(s).unwrap().scheduler;
        assert!(SchedulerConfig::into_scheduler(parse("")).is_ok());
        assert!(SchedulerConfig::into_scheduler(parse(r#"scheduler = "first-fit""#)).is_ok());
        assert!(SchedulerConfig::into_scheduler(parse(r#"scheduler = "bin-packing""#)).is_err());
    }

    /// The three shapes of "why is it Pending", as an operator reads them.
    /// Until this existed, the answer lived only in a debug line inside
    /// whichever replica happened to run the pass.
    #[test]
    fn a_pending_vm_can_say_which_of_the_three_reasons_it_is() {
        let nothing: [Candidate; 0] = [];
        assert!(pending_reason(&vm(), &nothing).contains("no candidates are known"));

        let asleep = [
            candidate("gone", false, true),
            candidate("draining", true, false),
        ];
        let msg = pending_reason(&vm(), &asleep);
        assert!(msg.contains("connected and schedulable"), "{msg}");
        assert!(msg.contains('2'), "it says how many it looked at: {msg}");

        // Asked for something nobody has: the message names exactly that.
        let plain = [gpu_candidate("agent-1a", &[])];
        let msg = pending_reason(&vm_asking(nvrm_4q()), &plain);
        assert!(msg.contains("nvrm/4q"), "{msg}");
    }

    /// The trap the lab walked into, and the reason this function has a third
    /// case: a cloud sees a CLUSTER catalogue, which is the UNION of its
    /// nodes'. Every part of the ask is served somewhere in that cluster and
    /// no single machine serves all of it — so the VM binds and then sits
    /// Pending forever, one tier down, with nothing to read.
    #[test]
    fn a_request_served_only_in_pieces_says_so_instead_of_naming_a_gap() {
        let union = [gpu_candidate("cluster-1", &["nvrm/4q", "network/vxlan"])];
        let spec = serde_json::json!({
            "devices": [{"driver": "nvrm", "profile": "4q"}],
            "nics": [{"vxlan_id": 10000}],
        });
        // Nothing is unmet — the union offers both — so the assign still
        // fails only one tier down. The sentence has to say that.
        let asked = DevicePolicy::of(&vm_asking(spec.clone()));
        assert!(asked.unmet(&union).is_empty(), "the union does offer both");
        let msg = pending_reason(&vm_asking(spec), &union);
        assert!(msg.contains("no single candidate"), "{msg}");
        assert!(msg.contains("each part is served somewhere"), "{msg}");
        assert!(
            msg.contains("nvrm/4q") && msg.contains("network/vxlan"),
            "{msg}"
        );
    }

    /// Every request must be served by ONE candidate — a combo VM (nvrm +
    /// crosvm) cannot be split across nodes.
    #[test]
    fn all_requests_must_fit_on_the_same_candidate() {
        let combo = serde_json::json!({"devices": [
            {"driver": "nvrm", "profile": "4q"},
            {"driver": "crosvm-gpu", "profile": "venus"},
        ]});
        let only_nvrm = [gpu_candidate("half", &["nvrm/4q"])];
        assert_eq!(FirstFit.assign(&vm_asking(combo.clone()), &only_nvrm), None);
        let both = [gpu_candidate("manacor", &["nvrm/4q", "crosvm-gpu/venus"])];
        assert_eq!(
            FirstFit.assign(&vm_asking(combo), &both).as_deref(),
            Some("manacor")
        );
    }
}

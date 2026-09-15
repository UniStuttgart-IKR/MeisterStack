// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Reading a peer's VM list against the VMs this tier stores.
//!
//! Both tiers do this with every status that arrives: the agent tells its
//! cluster the phase of each VM on the node, the cluster tells the cloud the
//! phase of each VM it holds for it, and both times the peer speaks uids while
//! the store is keyed by name — so the reported list doubles as the index.
//!
//! The rules are the same at both altitudes and live here: which stored VM a
//! reported uid is, whether the peer that sent it may speak for that VM at
//! all, whether the phase is one this control plane has, and whether anything
//! actually changed. What is NOT here is what each tier does with the answer:
//! an uid nobody knows is a debug line one floor down and a warning one floor
//! up, and where an observed phase is filed differs too. Those are decisions
//! about the tier, so they stay at the tier — see `Observation`.

use std::collections::HashMap;

use proto::VmStatusReport;

use crate::resources::{Vm, VmAddress, VmAddressKind, VmPhase, VmPhaseKind, VmReason};

/// Is a peer's report younger than everything this tier has already done?
/// Only then does it describe the thing as it is now.
///
/// The floor is whichever is later of "we asked for it to be deleted" and
/// "we last recorded an observation", because those are the two things this
/// tier did. A report built before either describes the world from before it,
/// and reading it as current would have us repeat a command that already took
/// — or, worse, accept a "gone" that answered an older question and delete an
/// object whose bytes were just made.
///
/// Loose over the two `Option`s and total, because both are genuinely absent
/// on a thing nobody has touched yet.
///
/// Here rather than beside either caller because both tiers ask it now, of
/// two different objects: the cloud of a `Vm` and the cluster of a `Volume`.
/// One rule, one place — the same argument the rest of this module makes.
pub fn is_current(
    deletion: Option<chrono::DateTime<chrono::Utc>>,
    observed: Option<chrono::DateTime<chrono::Utc>>,
    reported_at: chrono::DateTime<chrono::Utc>,
) -> bool {
    match deletion.max(observed) {
        // Not-older rather than strictly-younger: a status this tier already
        // wrote from carries exactly that instant, and it is evidence about
        // itself. Two different instants never compare equal here in
        // practice — this only readmits the status that set the floor.
        Some(floor) => reported_at >= floor,
        None => true,
    }
}

/// A VM's address list with the taps a peer just reported in it.
///
/// Here for the reason the rest of this module is: both tiers apply it, and
/// the two must agree exactly. The agent tells its cluster which taps it made
/// and the cluster tells the cloud the same thing off the object it wrote —
/// one rule, one place.
///
/// **An empty `reported` is not an answer and clears nothing.** A peer that
/// names no tap is a peer from before the field, and reading it as "this VM
/// has no addresses" would blank a working VM's list the moment an old binary
/// reconnected. A peer that names some replaces the MAC lines wholesale,
/// which is what makes a tap that has gone away drop out on its own.
///
/// Everything that is not a MAC line is kept untouched, because it belongs to
/// another writer — the cloud's floating addresses are the one there is. And
/// the MAC lines come FIRST, which is not cosmetic: the floating pass keeps
/// what it does not own and appends its own after it, so two passes that
/// agreed on the content and disagreed on the order would each read the
/// other's document as a change and rewrite it every ten seconds, for ever.
pub fn addresses_with(current: &[VmAddress], reported: &[proto::NicReport]) -> Vec<VmAddress> {
    if reported.is_empty() {
        return current.to_vec();
    }
    let mut out: Vec<VmAddress> = reported
        .iter()
        .map(|n| VmAddress {
            kind: VmAddressKind::Mac,
            nic: n.name.clone(),
            mac: Some(n.mac.clone()),
            // Never on a MAC line: the address a guest gave itself is known
            // to the guest and to nobody here, and there is no agent in there
            // to ask.
            address: None,
        })
        .collect();
    out.extend(
        current
            .iter()
            .filter(|a| a.kind != VmAddressKind::Mac)
            .cloned(),
    );
    out
}

/// What one line of a peer's report means for the VM it names. Everything
/// here is a case the caller has to answer for its own tier; the case that
/// needs no answer — a report that says exactly what is already stored — is
/// not in the list, because `observe` drops it.
#[derive(Debug)]
pub enum Observation<'a> {
    /// No stored VM carries this uid. Whether that is remarkable depends on
    /// the tier: an agent may be running VMs created straight on its own API,
    /// a cluster reporting a cloud-managed VM the cloud never created may not.
    Unknown,
    /// The VM is stored, but the peer that reported it is not the peer it is
    /// bound to — so its word about the phase is not evidence.
    NotBound(&'a Vm),
    /// The peer named a phase this control plane does not have. Rejected
    /// rather than defaulted: a drifting peer should be visible.
    BadPhase(&'a Vm),
    /// The report says something new about this VM: the phase the peer
    /// observed, the WORD it gave for why, and the sentence that came with it
    /// (absent when the peer sent none).
    ///
    /// The reason is the peer's own — `VmmGone`, `Backoff`, `BackendGone` —
    /// and not a word for the road it came down. It is read through
    /// `VmReason::read`, so a word this binary does not know arrives as
    /// `Unrecorded` with the word kept at the front of the sentence rather
    /// than dropped.
    Changed(&'a Vm, VmPhaseKind, VmReason, Option<String>),
}

/// Match a peer's report against the VMs this tier stores, one line at a time.
///
/// `speaks_for` is the binding question, and it is the caller's because the
/// two tiers bind differently — `spec.clusterName` one floor up,
/// `spec.nodeName` one floor down — and because how strict that question is
/// is a statement about the tier, not about mirroring.
///
/// A report that changes nothing yields nothing. Peers report every 10s, and
/// a write per report would churn etcd revisions — and wake the vm watch —
/// while nothing about the VM actually happened.
pub fn observe<'a>(
    known: &'a [Vm],
    reported: &'a [VmStatusReport],
    speaks_for: impl Fn(&Vm) -> bool + 'a,
) -> impl Iterator<Item = (&'a VmStatusReport, Observation<'a>)> {
    let by_uid: HashMap<&str, &Vm> = known.iter().map(|v| (v.metadata.uid.as_str(), v)).collect();
    reported.iter().filter_map(move |line| {
        let Some(vm) = by_uid.get(line.id.as_str()).copied() else {
            return Some((line, Observation::Unknown));
        };
        if !speaks_for(vm) {
            return Some((line, Observation::NotBound(vm)));
        }
        let Some(phase) = VmPhaseKind::parse(&line.phase) else {
            return Some((line, Observation::BadPhase(vm)));
        };
        let message = (!line.message.is_empty()).then(|| line.message.clone());
        let (reason, message) = VmReason::read(&line.reason, message);
        // Compared against the phase this report WOULD leave behind, not
        // against its three parts one by one, and that is not a flourish: a
        // resting word has no slot for a reason, so `Running` + `Working`
        // stores as `Running` with no reason at all. Held against the parts,
        // the stored value would differ from the report for ever and every
        // heartbeat of every running VM would be an etcd revision — D-C7, at
        // a second field. `since` is taken from the stored phase so that the
        // comparison is about the word, the reason and the sentence, which
        // are the three things a report carries.
        let candidate = VmPhase::new(phase, reason, message.clone(), vm.status.phase().since());
        if *vm.status.phase() == candidate {
            return None;
        }
        Some((line, Observation::Changed(vm, phase, reason, message)))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resources::{VmPhase, VmSpec, new_vm};

    fn vm(name: &str, uid: &str, node: Option<&str>) -> Vm {
        let mut vm = new_vm(
            name,
            VmSpec {
                class: Default::default(),
                cluster_selector: Default::default(),
                node_selector: Default::default(),
                anti_affinity: Vec::new(),
                node_name: node.map(str::to_string),
                cluster_name: None,
                run_strategy: Default::default(),
                evacuation: Default::default(),
                tenant: None,
                vm: serde_json::json!({}),
            },
        );
        vm.metadata.uid = uid.to_string();
        vm
    }

    fn line(uid: &str, phase: &str, message: &str) -> VmStatusReport {
        VmStatusReport {
            id: uid.into(),
            phase: phase.into(),
            message: message.into(),
            attached_volumes: Vec::new(),
            node: String::new(),
            volumes: Vec::new(),
            reason: String::new(),
            nics: Vec::new(),
        }
    }

    fn because(uid: &str, phase: &str, reason: &str, message: &str) -> VmStatusReport {
        VmStatusReport {
            reason: reason.into(),
            ..line(uid, phase, message)
        }
    }

    /// The binding is the caller's question, so these tests ask it the way
    /// the cluster tier does: a VM speaks for the node its spec names.
    fn bound_to<'a>(node: &'a str) -> impl Fn(&Vm) -> bool + 'a {
        move |vm: &Vm| vm.spec.node_name.as_deref() == Some(node)
    }

    fn seen<'a>(
        known: &'a [Vm],
        reported: &'a [VmStatusReport],
        node: &'a str,
    ) -> Vec<Observation<'a>> {
        observe(known, reported, bound_to(node))
            .map(|(_, o)| o)
            .collect()
    }

    #[test]
    fn a_reported_uid_finds_its_vm_by_uid_and_not_by_name() {
        let known = [vm("web-1", "uid-a", Some("manacor"))];
        let reported = [line("uid-a", "Running", "")];
        assert!(matches!(
            seen(&known, &reported, "manacor").as_slice(),
            [Observation::Changed(vm, VmPhaseKind::Running, VmReason::Unrecorded, None)]
                if vm.metadata.name == "web-1"
        ));
    }

    /// The three refusals, each of which the caller answers in its own words.
    #[test]
    fn an_unknown_uid_a_foreign_reporter_and_a_phase_we_do_not_have_are_each_named() {
        let known = [
            vm("web-1", "uid-a", Some("manacor")),
            vm("web-2", "uid-b", Some("other")),
        ];
        let reported = [
            line("uid-nobody", "Running", ""),
            line("uid-b", "Running", ""),
            line("uid-a", "Ascended", ""),
        ];
        assert!(matches!(
            seen(&known, &reported, "manacor").as_slice(),
            [
                Observation::Unknown,
                Observation::NotBound(_),
                Observation::BadPhase(_)
            ]
        ));
    }

    /// The rule that keeps a 10s report from churning etcd: only a difference
    /// is an observation. The message counts as part of it — a phase that
    /// stayed while its reason changed is news.
    #[test]
    fn a_report_that_says_what_is_already_stored_yields_nothing() {
        let mut stored = vm("web-1", "uid-a", Some("manacor"));
        #[allow(deprecated)]
        stored
            .status
            .assign(VmPhase::of(VmPhaseKind::Running, chrono::Utc::now()));
        let known = [stored];

        assert!(seen(&known, &[line("uid-a", "Running", "")], "manacor").is_empty());
        assert_eq!(
            seen(&known, &[line("uid-a", "Stopped", "")], "manacor").len(),
            1,
            "a new phase is news"
        );
        assert!(
            matches!(
                seen(&known, &[line("uid-a", "Running", "host rebooted")], "manacor").as_slice(),
                [Observation::Changed(_, VmPhaseKind::Running, _, Some(m))]
                    if m == "host rebooted"
            ),
            "so is a new message under an unchanged phase"
        );
    }

    /// An empty message is "the peer said nothing", not "the peer said the
    /// empty string" — otherwise every clearing report would be a write.
    #[test]
    fn an_empty_message_is_absent_rather_than_empty() {
        let mut stored = vm("web-1", "uid-a", Some("manacor"));
        #[allow(deprecated)]
        stored.status.assign(VmPhase::said(
            VmPhaseKind::Failed,
            Some("out of memory".into()),
            chrono::Utc::now(),
        ));
        let known = [stored];
        assert!(matches!(
            seen(&known, &[line("uid-a", "Failed", "")], "manacor").as_slice(),
            [Observation::Changed(
                _,
                VmPhaseKind::Failed,
                VmReason::Unrecorded,
                None
            )]
        ));
    }

    fn mac(nic: &str, addr: &str) -> VmAddress {
        VmAddress {
            kind: VmAddressKind::Mac,
            nic: nic.into(),
            mac: Some(addr.into()),
            address: None,
        }
    }

    fn floating(addr: &str) -> VmAddress {
        VmAddress {
            kind: VmAddressKind::FloatingIp,
            nic: String::new(),
            mac: None,
            address: Some(addr.into()),
        }
    }

    fn tap(name: &str, addr: &str) -> proto::NicReport {
        proto::NicReport {
            name: name.into(),
            mac: addr.into(),
        }
    }

    /// The whole point of the field, and the half that is a rule rather than
    /// a copy: what a peer reports REPLACES the MAC lines, so a tap that has
    /// gone away drops out on its own report, and it leaves everything else
    /// exactly where it was, because the other lines have another writer.
    #[test]
    fn the_reported_taps_replace_the_mac_lines_and_leave_the_rest() {
        let current = [
            mac("nics[0]", "52:54:00:00:00:01"),
            mac("nics[1]", "52:54:00:00:00:02"),
            floating("192.0.2.7"),
        ];
        let out = addresses_with(&current, &[tap("nics[0]", "52:54:00:00:00:01")]);
        assert_eq!(
            out,
            vec![mac("nics[0]", "52:54:00:00:00:01"), floating("192.0.2.7")],
            "the second tap is gone and the floating address is not this writer's to touch"
        );

        // MAC lines first, because the floating pass keeps what it does not
        // own and appends its own after it. Two writers that disagreed about
        // the order would rewrite each other's document every ten seconds.
        assert_eq!(out[0].kind, VmAddressKind::Mac);
    }

    /// A peer that names no tap is a peer from before the field — an old
    /// agent to a cluster, an old cluster to a cloud — and it says NOTHING
    /// about addresses. Not "none": nothing. Reading it the other way would
    /// blank a working VM's list the moment an old binary reconnected.
    #[test]
    fn a_peer_that_reports_no_tap_leaves_the_addresses_exactly_as_they_were() {
        let current = [mac("nics[0]", "52:54:00:00:00:01"), floating("192.0.2.7")];
        assert_eq!(addresses_with(&current, &[]), current.to_vec());
        // Including on a VM that has none, where the difference does not
        // show but the rule is the same one.
        assert!(addresses_with(&[], &[]).is_empty());
    }

    /// A VM whose taps this peer is the first to report: the list is what it
    /// said, in the order it said it.
    #[test]
    fn the_first_report_of_a_tap_is_the_whole_answer() {
        let out = addresses_with(
            &[],
            &[
                tap("nics[0]", "52:54:00:11:22:33"),
                tap("nics[1]", "52:54:00:aa:bb:cc"),
            ],
        );
        assert_eq!(
            out,
            vec![
                mac("nics[0]", "52:54:00:11:22:33"),
                mac("nics[1]", "52:54:00:aa:bb:cc"),
            ]
        );
    }

    /// The node's own word arrives on the object, and a word this tier does
    /// not know arrives too — at the front of the sentence.
    ///
    /// The whole of decision 1 as it reaches a VM: the phase used to come up
    /// with "Reported" beside it, which said which ROAD it came down and
    /// never what had happened. `VmmGone` and `BackendGone` are two different
    /// problems — the requeue curve repairs the first and must not touch the
    /// second — and they were the same value.
    #[test]
    fn the_word_the_peer_gave_is_the_word_on_the_observation() {
        let known = [vm("web-1", "uid-a", Some("manacor"))];

        let reported = [because(
            "uid-a",
            "Quarantined",
            "BackendGone",
            "the backend died",
        )];
        assert!(matches!(
            seen(&known, &reported, "manacor").as_slice(),
            [Observation::Changed(_, VmPhaseKind::Quarantined, VmReason::BackendGone, Some(m))]
                if m == "the backend died"
        ));

        // A word from a newer agent than this binary: not dropped, because
        // "I was told something I do not understand" must not read as
        // "nobody said anything" (decision 2).
        let drifted = [because("uid-a", "Failed", "Ascended", "it left")];
        assert!(matches!(
            seen(&known, &drifted, "manacor").as_slice(),
            [Observation::Changed(_, VmPhaseKind::Failed, VmReason::Unrecorded, Some(m))]
                if m == "Ascended: it left"
        ));
    }

    /// The churn guard, held against the case that would break it: a running
    /// VM whose node sends `Working` on every heartbeat.
    ///
    /// A resting word has no slot for a reason, so the stored phase carries
    /// none — and a guard that compared the report's reason against the
    /// stored one would find them different for ever. That is an etcd
    /// revision per VM per ten seconds to record that nothing happened, which
    /// is the defect this round fixes one field over (D-C7).
    #[test]
    fn a_reason_on_a_resting_word_does_not_make_a_report_news() {
        let mut stored = vm("web-1", "uid-a", Some("manacor"));
        #[allow(deprecated)]
        stored.status.assign(VmPhase::new(
            VmPhaseKind::Running,
            VmReason::Working,
            None,
            chrono::Utc::now(),
        ));
        let known = [stored];
        assert!(
            seen(
                &known,
                &[because("uid-a", "Running", "Working", "")],
                "manacor"
            )
            .is_empty(),
            "the reason had nowhere to be stored, so it cannot be a difference"
        );

        // And a reasoned word does compare: the same phase with a new reason
        // IS news, because the requeue curve reads it.
        let mut stored = vm("web-2", "uid-b", Some("manacor"));
        #[allow(deprecated)]
        stored.status.assign(VmPhase::new(
            VmPhaseKind::Failed,
            VmReason::VmmGone,
            Some("gone".into()),
            chrono::Utc::now(),
        ));
        let known = [stored];
        assert!(
            seen(
                &known,
                &[because("uid-b", "Failed", "ReceiveFailed", "gone")],
                "manacor"
            )
            .len()
                == 1
        );
        assert!(
            seen(
                &known,
                &[because("uid-b", "Failed", "VmmGone", "gone")],
                "manacor"
            )
            .is_empty()
        );
    }
}

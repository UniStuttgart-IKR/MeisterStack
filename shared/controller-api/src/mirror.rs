// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Match peer VM reports to stored objects by UID and placement.
//!
//! Reject reports from a peer that does not own the binding, decode phases and
//! identify changes. Each controller tier decides how to persist or log the
//! resulting observation.

use std::collections::HashMap;

use proto::VmStatusReport;

use crate::resources::{Vm, VmAddress, VmAddressKind, VmPhase, VmPhaseKind, VmReason};

/// Check report freshness against deletion request and last observation.
/// Reject evidence older than either floor; stale absence cannot authorize
/// cleanup. An unset floor imposes no timestamp constraint.
pub fn is_current(
    deletion: Option<chrono::DateTime<chrono::Utc>>,
    observed: Option<chrono::DateTime<chrono::Utc>>,
    reported_at: chrono::DateTime<chrono::Utc>,
) -> bool {
    match deletion.max(observed) {
        // Accept equality with the evidence floor so the report that established
        // that floor remains usable. This does not distinguish equal-timestamp reports.
        Some(floor) => reported_at >= floor,
        None => true,
    }
}

/// Replace reported MAC entries while preserving addresses owned by other
/// writers. An empty report clears nothing for compatibility with older peers.
/// MAC entries come first so this writer and the floating-address reconciler
/// agree on order and avoid repeated no-op updates.
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

/// Changed or unmatched peer observations requiring a tier-specific response.
/// Unchanged reports are omitted by `observe`.
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
    /// Changed phase and peer reason/message. Unknown reason strings are
    /// retained in the message by `VmReason::read` for older readers.
    Changed(&'a Vm, VmPhaseKind, VmReason, Option<String>),
}

/// Match reports to stored VMs using the caller's binding predicate.
/// Yield only meaningful changes to avoid an etcd write and watch wakeup
/// for each unchanged heartbeat.
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
        // Compare the settled phase shape while retaining its existing since
        // time. Resting phases discard reasons; comparing raw report parts
        // would therefore rewrite an unchanged Running VM on every heartbeat.
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
    use crate::resources::{VmSpec, new_vm};

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

    /// A VM its node has already said something about, through the
    /// derivation — the only way in since struktur 4.
    fn said_to_be(mut vm: Vm, phase: VmPhaseKind, reason: VmReason, message: Option<String>) -> Vm {
        vm.status.reported = Some(crate::VmReported::by(
            "manacor",
            phase,
            reason,
            message,
            chrono::Utc::now(),
        ));
        crate::object::Resource::settle(&mut vm, chrono::Utc::now());
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
        let known = [said_to_be(
            vm("web-1", "uid-a", Some("manacor")),
            VmPhaseKind::Running,
            VmReason::Unrecorded,
            None,
        )];

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
        let known = [said_to_be(
            vm("web-1", "uid-a", Some("manacor")),
            VmPhaseKind::Failed,
            VmReason::Unrecorded,
            Some("out of memory".into()),
        )];
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

    /// A nonempty MAC report replaces prior MAC entries while preserving addresses
    /// owned by other writers.
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

    /// Empty tap reports preserve addresses for compatibility with older peers;
    /// they cannot distinguish an empty current inventory from an omitted field.
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

    /// Preserve known peer reason codes and include unknown codes in the message
    /// so runtime causes remain distinguishable across version skew.
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

    /// Ignore reason differences that cannot be represented by a resting phase,
    /// avoiding unchanged VM rewrites on every heartbeat.
    #[test]
    fn a_reason_on_a_resting_word_does_not_make_a_report_news() {
        let known = [said_to_be(
            vm("web-1", "uid-a", Some("manacor")),
            VmPhaseKind::Running,
            VmReason::Working,
            None,
        )];
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
        let known = [said_to_be(
            vm("web-2", "uid-b", Some("manacor")),
            VmPhaseKind::Failed,
            VmReason::VmmGone,
            Some("gone".into()),
        )];
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

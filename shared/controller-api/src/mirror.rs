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

use macros::generated;
use proto::VmStatusReport;

use crate::resources::{Vm, VmPhase};

/// What one line of a peer's report means for the VM it names. Everything
/// here is a case the caller has to answer for its own tier; the case that
/// needs no answer — a report that says exactly what is already stored — is
/// not in the list, because `observe` drops it.
#[derive(Debug)]
#[generated(model = ClaudeOpus, version = "5")]
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
    /// The report says something new about this VM: the phase it observed and
    /// the message that came with it (absent when the peer sent none).
    Changed(&'a Vm, VmPhase, Option<String>),
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
#[generated(model = ClaudeOpus, version = "5")]
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
        let Some(phase) = VmPhase::parse(&line.phase) else {
            return Some((line, Observation::BadPhase(vm)));
        };
        let message = (!line.message.is_empty()).then(|| line.message.clone());
        if vm.status.phase == phase && vm.status.message == message {
            return None;
        }
        Some((line, Observation::Changed(vm, phase, message)))
    })
}

#[cfg(test)]
#[generated(model = ClaudeOpus, version = "5")]
mod tests {
    use super::*;
    use crate::resources::{VmSpec, new_vm};

    fn vm(name: &str, uid: &str, node: Option<&str>) -> Vm {
        let mut vm = new_vm(
            name,
            VmSpec {
                node_name: node.map(str::to_string),
                cluster_name: None,
                run_strategy: Default::default(),
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
            [Observation::Changed(vm, VmPhase::Running, None)] if vm.metadata.name == "web-1"
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
        stored.status.phase = VmPhase::Running;
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
                [Observation::Changed(_, VmPhase::Running, Some(m))] if m == "host rebooted"
            ),
            "so is a new message under an unchanged phase"
        );
    }

    /// An empty message is "the peer said nothing", not "the peer said the
    /// empty string" — otherwise every clearing report would be a write.
    #[test]
    fn an_empty_message_is_absent_rather_than_empty() {
        let mut stored = vm("web-1", "uid-a", Some("manacor"));
        stored.status.phase = VmPhase::Failed;
        stored.status.message = Some("out of memory".into());
        let known = [stored];
        assert!(matches!(
            seen(&known, &[line("uid-a", "Failed", "")], "manacor").as_slice(),
            [Observation::Changed(_, VmPhase::Failed, None)]
        ));
    }
}

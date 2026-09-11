// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The verbs that are about the controller's picture of this node rather
//! than about one VM: the whole desired state at once, and what a guest has
//! printed.

use super::*;

impl Agent {
    /// The whole desired state of this node in one message. Every entry is an
    /// idempotent create; what is *missing* is the other half of the message —
    /// a managed record the controller no longer lists was deleted while this
    /// agent was away, and the reconciler tears it down.
    #[instrument(skip_all, fields(vms = sync.desired.len()))]
    pub(crate) async fn handle_sync_state(&self, sync: proto::SyncState) -> anyhow::Result<()> {
        let mut snapshot: HashSet<VmId> = HashSet::new();
        let mut failures: Vec<String> = Vec::new();

        // An unparsable id is noted and skipped rather than nested around
        // the work: it cannot go into the snapshot, so letting it fall
        // through would put an id nobody can name into the orphan sweep.
        for create in sync.desired {
            let raw = create.id.clone();
            let id = match raw.parse::<VmId>() {
                Ok(id) => id,
                Err(e) => {
                    failures.push(format!("invalid vm id {raw:?}: {e}"));
                    continue;
                }
            };
            snapshot.insert(id);
            if let Err(e) = self.handle_create(create).await {
                failures.push(format!("vm {id}: {e:#}"));
            }
        }

        // The sweep runs even when an entry failed: a VM this node could not
        // apply says nothing about the ones the controller dropped.
        let records = self.store.list()?;
        for id in sync_orphans(&snapshot, records.iter().map(|(id, r)| (*id, r))) {
            info!(vm_id = %id, "not in the controller's desired state, tearing down");
            if let Err(e) = self.set_desired(id, Desired::Absent).await {
                failures.push(format!("vm {id}: teardown: {e:#}"));
            }
        }

        if failures.is_empty() {
            Ok(())
        } else {
            bail!(
                "{} of the desired state did not apply: {}",
                failures.len(),
                failures.join("; ")
            )
        }
    }

    /// The end of a VM's one-way output, as the JSON the whole way up.
    ///
    /// The same document the node's own REST API serves, passed through the
    /// cluster and the cloud without either of them opening it: what a
    /// console printed is the node's answer, and a tier that reformatted it
    /// would be a tier that could get it wrong.
    ///
    /// A vm this node has no record of is `NoSuchVm` — the same error every
    /// other command gives for the same thing, so it is logged at the same
    /// level and repaired by the same SyncState. A vm that has simply printed
    /// nothing answers with an empty list.
    pub(super) fn handle_logs(&self, cmd: proto::FetchLogs) -> anyhow::Result<Vec<u8>> {
        let id: VmId = cmd.id.parse().context("invalid vm id")?;
        if self.store.get(&id)?.is_none() {
            return Err(NoSuchVm(id).into());
        }
        let lines = match cmd.lines {
            0 => crate::console::DEFAULT_LINES,
            n => n as usize,
        };
        let keep = crate::console::LogFilter::new(cmd.hide.clone(), cmd.only.clone());
        // Naming none is naming the default: the guest's streams, not the
        // VMM's own diagnostics.
        let wanted: Vec<ConsoleStream> = match cmd.streams.is_empty() {
            true => ConsoleStream::ALL.to_vec(),
            false => cmd
                .streams
                .iter()
                .filter_map(|s| ConsoleStream::parse(s))
                .collect(),
        };
        let streams: Vec<serde_json::Value> = self
            .reconciler
            .console(&id, lines, &keep, &wanted)
            .into_iter()
            .map(|(stream, text)| serde_json::json!({"stream": stream.as_str(), "text": text}))
            .collect();
        Ok(serde_json::to_vec(&streams)?)
    }
}

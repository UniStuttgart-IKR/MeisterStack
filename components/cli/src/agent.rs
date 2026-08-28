// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! `meister agent …` — drives one node's own REST api, over its unix socket.
//!
//! The bottom tier, and the only one with no api machinery under it: ids are
//! the node's, listings are bare arrays, and `observe`/`reconcile` exist here
//! and nowhere above because they are questions about one node's processes.

use anyhow::{Context, Result};
use macros::generated;
use serde::Deserialize;

use crate::client::Client;
use crate::config::Target;
use crate::output::{self, View, or_dash};
use crate::{AgentCmd, GlobalArgs};

#[derive(Deserialize)]
struct VmListEntry {
    id: String,
    #[serde(default)]
    desired: Option<String>,
    phase: Option<String>,
    #[serde(default)]
    unhealthy: Option<String>,
    readable: bool,
}

#[derive(Deserialize)]
struct ObserveResponse {
    #[serde(default)]
    desired: Option<String>,
    phase: String,
    #[serde(default)]
    unhealthy: Option<String>,
    observed: Observed,
    action: String,
}

#[derive(Deserialize)]
struct Observed {
    tracked: bool,
    vmm_alive: bool,
    socket_responsive: bool,
    /// Every backend process the VM has — device and volume alike. Renamed
    /// with the agent's field: `serde(default)` means a mismatch here shows
    /// a confident `false` rather than an error, so the two names have to be
    /// kept in step by hand.
    #[serde(default)]
    backends_alive: bool,
    #[serde(default)]
    guest: Option<String>,
}

#[derive(Deserialize)]
struct ActionResponse {
    action: String,
}

#[derive(Deserialize)]
struct CreatedResponse {
    id: String,
}

/// Every verb of this tier that destroys something, and the whole list of it.
/// See the same function at the two tiers above.
#[generated(model = ClaudeOpus, version = "5")]
fn destructive(cmd: &AgentCmd) -> Option<(&'static str, &str)> {
    match cmd {
        AgentCmd::Destroy { id } => Some(("vm", id)),
        _ => None,
    }
}

#[generated(model = ClaudeOpus, version = "4.8")]
pub async fn run(target: &Target, cmd: &AgentCmd, global: &GlobalArgs) -> Result<()> {
    if let Some((kind, name)) = destructive(cmd) {
        output::confirm_destructive(global, target, kind, name)?;
    }

    let client = Client::new(target)?;

    match cmd {
        AgentCmd::Ls => {
            let body = client.get("/vms").await?;
            output::emit(global, &body, |body| {
                output::table_of_array(
                    body,
                    "parsing /vms response",
                    &["id", "desired", "phase", "health", "note"],
                    "no vms on this node",
                    vm_row,
                )
            })
        }

        // No name to create under and none to look one up by at this tier:
        // the node assigns the id, so `create` takes only a spec and prints
        // what it was given.
        AgentCmd::Create { spec } => {
            let raw = std::fs::read(spec)
                .with_context(|| format!("reading spec file {}", spec.display()))?;
            serde_json::from_slice::<serde_json::Value>(&raw)
                .with_context(|| format!("spec file {} is not valid json", spec.display()))?;

            let body = client.post("/vms", Some(raw)).await?;
            output::emit(global, &body, |body| {
                let created: CreatedResponse =
                    serde_json::from_slice(body).context("parsing create response")?;
                Ok(View::line(created.id))
            })
        }

        AgentCmd::Inspect { id } => {
            output::print_json(&client.get(&format!("/vms/{id}")).await?);
            Ok(())
        }

        // What the node sees against what it was asked for, and what it would
        // do about the difference. There is no such verb one tier up because
        // there is nothing there to look at: a controller knows what a node
        // reported, not what its processes are doing.
        AgentCmd::Observe { id } => {
            let body = client.get(&format!("/vms/{id}/observe")).await?;
            output::emit(global, &body, |body| {
                let o: ObserveResponse =
                    serde_json::from_slice(body).context("parsing observe response")?;
                Ok(output::fields(observe_rows(o)))
            })
        }

        // The reconcile loop's one step, asked for by hand. Above this tier
        // the controllers run it themselves, on their own clock.
        AgentCmd::Reconcile { id } => {
            let body = client.post(&format!("/vms/{id}/reconcile"), None).await?;
            action(global, &body, "parsing reconcile response")
        }

        AgentCmd::Destroy { id } => {
            let body = client.delete(&format!("/vms/{id}")).await?;
            output::emit(global, &body, |body| {
                // An older node answers a delete with nothing at all, and a
                // delete that said nothing still worked.
                Ok(match serde_json::from_slice::<ActionResponse>(body) {
                    Ok(r) => View::line(r.action),
                    Err(_) => View::line("ok"),
                })
            })
        }

        AgentCmd::Start { id } => lifecycle(&client, global, &format!("/vms/{id}/start")).await,
        // The only tier that takes a grace period, because it is the only one
        // that waits it out: above this, `stop` writes a runStrategy and the
        // node it lands on applies its own.
        AgentCmd::Stop { id, grace } => {
            let path = match grace {
                Some(g) => format!("/vms/{id}/stop?grace_secs={g}"),
                None => format!("/vms/{id}/stop"),
            };
            lifecycle(&client, global, &path).await
        }
        AgentCmd::Pause { id } => lifecycle(&client, global, &format!("/vms/{id}/pause")).await,
        AgentCmd::Resume { id } => lifecycle(&client, global, &format!("/vms/{id}/resume")).await,
    }
}

/// The listing row. `note` is last on purpose: see the rule in
/// [`crate::output`].
#[generated(model = ClaudeOpus, version = "5")]
fn vm_row(v: VmListEntry) -> Vec<String> {
    vec![
        v.id,
        or_dash(v.desired),
        or_dash(v.phase),
        // The reason belongs in `observe`; the listing says only whether
        // there is one.
        if v.unhealthy.is_some() {
            "unhealthy".into()
        } else {
            "ok".into()
        },
        if v.readable {
            "".into()
        } else {
            "unreadable".into()
        },
    ]
}

#[generated(model = ClaudeOpus, version = "5")]
fn observe_rows(o: ObserveResponse) -> Vec<Vec<String>> {
    let field = |name: &str, value: String| vec![name.to_string(), value];
    vec![
        field("desired", or_dash(o.desired)),
        field("phase", o.phase),
        field("unhealthy", or_dash(o.unhealthy)),
        field("tracked", o.observed.tracked.to_string()),
        field("vmm_alive", o.observed.vmm_alive.to_string()),
        field(
            "socket_responsive",
            o.observed.socket_responsive.to_string(),
        ),
        field("backends_alive", o.observed.backends_alive.to_string()),
        field("guest", or_dash(o.observed.guest)),
        field("action", o.action),
    ]
}

/// What the node did, or would have done. Every verb of this tier that acts
/// answers in this one shape.
#[generated(model = ClaudeOpus, version = "5")]
fn action(global: &GlobalArgs, body: &bytes::Bytes, parsing: &'static str) -> Result<()> {
    output::emit(global, body, |body| {
        let r: ActionResponse = serde_json::from_slice(body).context(parsing)?;
        Ok(View::line(r.action))
    })
}

#[generated(model = ClaudeFable, version = "5")]
async fn lifecycle(client: &Client, global: &GlobalArgs, path: &str) -> Result<()> {
    let body = client.post(path, None).await?;
    action(global, &body, "parsing lifecycle response")
}

#[cfg(test)]
#[generated(model = ClaudeOpus, version = "5")]
mod tests {
    use super::*;

    /// A vm the node cannot read the state of is still a vm it knows about,
    /// and the row has to say which of the two it is in every column.
    #[test]
    fn an_unreadable_vm_still_renders_a_full_row() {
        let entry: VmListEntry =
            serde_json::from_str(r#"{"id":"vm-1","phase":null,"readable":false}"#).unwrap();
        assert_eq!(vm_row(entry), vec!["vm-1", "-", "-", "ok", "unreadable"]);
    }

    /// The listing says whether there is a reason, not what it is: the reason
    /// is a sentence, and a sentence in a middle column shifts every field
    /// behind it.
    #[test]
    fn the_health_column_stays_one_token() {
        let entry: VmListEntry = serde_json::from_str(
            r#"{"id":"vm-1","desired":"Running","phase":"Crashed",
                "unhealthy":"vmm process is gone","readable":true}"#,
        )
        .unwrap();
        let row = vm_row(entry);
        assert_eq!(row[3], "unhealthy");
        for cell in &row[..row.len() - 1] {
            assert!(!cell.contains(' '), "{cell:?} carries a raw space");
        }
    }
}

// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! `meister agent vm …` — the node itself, over its own socket.
//!
//! A different api and not a third tier of the same one: there is no
//! discovery here, no objects, no names — ids are the node's — listings are
//! bare arrays, and `observe` and `reconcile` exist here and nowhere above
//! because they are questions about one machine's processes. So the CLI never
//! asks a unix endpoint what group-version it serves; a unix endpoint IS a
//! node, by definition, and pointing anything else at one is a sentence.

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::client::Client;
use crate::config::Target;
use crate::output::{self, View, or_dash};
use crate::{AgentCmd, AgentVmCmd, AgentVolumeCmd, GlobalArgs};

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

/// What the NODE thinks it holds, which is a different question from what the
/// `Volume` objects say — and the one worth asking when the two disagree.
///
/// Read-only by construction: there are no write routes at the socket for
/// volumes, so there are no verbs here for them either. `Gone` rows are shown
/// rather than filtered: a volume the node has just deprovisioned is exactly
/// the one somebody is looking for.
async fn volume(target: &Target, cmd: &AgentVolumeCmd, global: &GlobalArgs) -> Result<()> {
    let client = Client::new(target)?;
    match cmd {
        AgentVolumeCmd::Ls => {
            let body = client.get("/volumes").await?;
            output::emit(global, &body, |body| {
                output::table_of_array(
                    body,
                    "parsing /volumes response",
                    &["id", "phase", "driver", "size", "backend", "attached-to"],
                    "no volumes on this node",
                    volume_row,
                )
            })
        }
        // Whole, like `agent vm get`: what is being asked for is the record
        // itself, and a table would be this CLI deciding which half of it
        // matters.
        AgentVolumeCmd::Get { id } => {
            let _ = global;
            output::print_json(&client.get(&format!("/volumes/{id}")).await?);
            Ok(())
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
struct VolumeEntry {
    id: String,
    phase: String,
    #[serde(default)]
    backend: String,
    #[serde(default)]
    size_bytes: u64,
    #[serde(default)]
    driver: String,
    #[serde(default)]
    attached_to: Option<String>,
}

fn volume_row(v: VolumeEntry) -> Vec<String> {
    vec![
        v.id,
        v.phase,
        v.driver,
        gib(v.size_bytes),
        // Empty is the window between "told to make it" and "made it", and a
        // dash reads as that rather than as a path somebody has to squint at.
        if v.backend.is_empty() {
            "-".to_string()
        } else {
            v.backend
        },
        v.attached_to.unwrap_or_else(|| "-".to_string()),
    ]
}

/// Bytes as the unit an operator writes on a whiteboard. Rounded down and
/// never to zero: a volume smaller than a GiB is a real thing (a share is
/// reported as zero bytes) and printing `0Gi` for it would be a number.
fn gib(bytes: u64) -> String {
    match bytes {
        0 => "-".to_string(),
        n if n < 1024 * 1024 * 1024 => format!("{}Mi", n / (1024 * 1024)),
        n => format!("{}Gi", n / (1024 * 1024 * 1024)),
    }
}

pub async fn run(target: &Target, cmd: &AgentCmd, global: &GlobalArgs) -> Result<()> {
    let cmd = match cmd {
        AgentCmd::Vm { cmd } => cmd,
        AgentCmd::Volume { cmd } => return volume(target, cmd, global).await,
    };
    if let AgentVmCmd::Rm { id } = cmd {
        output::confirm(
            global,
            &target.endpoint,
            &target.profile_name,
            "delete",
            "vm",
            id,
        )?;
    }

    let client = Client::new(target)?;

    match cmd {
        AgentVmCmd::Ls => {
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
        AgentVmCmd::Create { file } => {
            let raw = std::fs::read(file)
                .with_context(|| format!("reading spec file {}", file.display()))?;
            serde_json::from_slice::<serde_json::Value>(&raw)
                .with_context(|| format!("spec file {} is not valid json", file.display()))?;

            let body = client.post("/vms", Some(raw)).await?;
            output::emit(global, &body, |body| {
                let created: CreatedResponse =
                    serde_json::from_slice(body).context("parsing create response")?;
                Ok(View::line(created.id))
            })
        }

        // The node's own ring, read straight off it — one hop instead of the
        // two a controller tier takes, and the same document either way.
        AgentVmCmd::Logs {
            id,
            lines,
            hide,
            only,
            streams,
        } => {
            logs(
                &client,
                global,
                id,
                *lines,
                &crate::vm::LogFilter::new(hide, only, streams),
            )
            .await
        }

        AgentVmCmd::Get { id } => {
            output::print_json(&client.get(&format!("/vms/{id}")).await?);
            Ok(())
        }

        // What the node sees against what it was asked for, and what it would
        // do about the difference. There is no such verb one tier up because
        // there is nothing there to look at: a controller knows what a node
        // reported, not what its processes are doing.
        AgentVmCmd::Observe { id } => {
            let body = client.get(&format!("/vms/{id}/observe")).await?;
            output::emit(global, &body, |body| {
                let o: ObserveResponse =
                    serde_json::from_slice(body).context("parsing observe response")?;
                Ok(output::fields(observe_rows(o)))
            })
        }

        // The reconcile loop's one step, asked for by hand. Above this tier
        // the controllers run it themselves, on their own clock.
        AgentVmCmd::Reconcile { id } => {
            let body = client.post(&format!("/vms/{id}/reconcile"), None).await?;
            action(global, &body, "parsing reconcile response")
        }

        AgentVmCmd::Rm { id } => {
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

        AgentVmCmd::Start { id } => lifecycle(&client, global, &format!("/vms/{id}/start")).await,
        // The only tier that takes a grace period, because it is the only one
        // that waits it out: above this, `stop` writes a runStrategy and the
        // node it lands on applies its own.
        AgentVmCmd::Stop { id, grace } => {
            let path = match grace {
                Some(g) => format!("/vms/{id}/stop?grace_secs={g}"),
                None => format!("/vms/{id}/stop"),
            };
            lifecycle(&client, global, &path).await
        }
        AgentVmCmd::Pause { id } => lifecycle(&client, global, &format!("/vms/{id}/pause")).await,
        AgentVmCmd::Resume { id } => lifecycle(&client, global, &format!("/vms/{id}/resume")).await,
    }
}

/// What the guest printed, straight off this node's own ring.
///
/// The same document the two tiers above serve, one hop instead of two — and
/// printed as text rather than as a table, because a console is lines and a
/// table cell with a kernel oops in it is a table nobody can read.
async fn logs(
    client: &Client,
    global: &GlobalArgs,
    id: &str,
    lines: Option<u32>,
    keep: &crate::vm::LogFilter,
) -> Result<()> {
    let body = client
        .get(&format!("/vms/{id}/logs{}", keep.query(lines)))
        .await?;
    output::emit(global, &body, |body| {
        let streams: Vec<crate::vm::LogStream> =
            serde_json::from_slice(body).context("parsing the console output")?;
        Ok(View::text(crate::vm::render_logs(&streams)))
    })
}

/// The listing row. `note` is last on purpose: see the rule in
/// [`crate::output`].
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
fn action(global: &GlobalArgs, body: &bytes::Bytes, parsing: &'static str) -> Result<()> {
    output::emit(global, body, |body| {
        let r: ActionResponse = serde_json::from_slice(body).context(parsing)?;
        Ok(View::line(r.action))
    })
}

async fn lifecycle(client: &Client, global: &GlobalArgs, path: &str) -> Result<()> {
    let body = client.post(path, None).await?;
    action(global, &body, "parsing lifecycle response")
}

#[cfg(test)]
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

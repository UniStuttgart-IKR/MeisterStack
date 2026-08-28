// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Asking the node a VM is bound to for what its guest printed.
//!
//! One function, two callers: this tier's own REST route and the cloud's
//! FetchVmLogs command. Both want the same thing — the node's document,
//! unopened — and having them ask through one place is what keeps the two
//! answers from drifting apart.
//!
//! Nothing here reads or reshapes the document. What a console printed is the
//! node's answer; a tier that reformatted it on the way through would be a
//! tier that could get it wrong, and there are two of them above the node.

use controller_api::Vm;
use macros::generated;
use proto::command;

use crate::session::SessionRegistry;

/// What the fetch found. Not being placed yet is an ANSWER and not a failure:
/// a Pending VM has printed nothing because nothing has started, which is the
/// commonest true thing to say about one.
#[generated(model = ClaudeOpus, version = "5")]
pub enum Logs {
    /// The node's JSON document, verbatim.
    From(Vec<u8>),
    /// The VM is not on a node. The sentence says which of the two reasons.
    NotYet(String),
}

/// The empty document, which is what `NotYet` renders as at a REST edge: an
/// empty list of streams, in the same shape a node would have sent.
pub const NO_STREAMS: &[u8] = b"[]";

/// Ask this VM's node for the end of its output.
///
/// An error here is always about reaching the node — no session, a session
/// that would not take the command, a node that did not answer — and never
/// about the VM. The caller turns that into a 503, because "I could not reach
/// the thing that has the answer" is a different sentence from "there is no
/// answer".
#[generated(model = ClaudeOpus, version = "5")]
pub async fn fetch(
    registry: &SessionRegistry,
    vm: &Vm,
    lines: u32,
    traceparent: &str,
) -> anyhow::Result<Logs> {
    let Some(node) = vm.spec.node_name.as_deref() else {
        return Ok(Logs::NotYet(format!(
            "vm {} is not placed on a node yet, so nothing has printed anything",
            vm.metadata.name
        )));
    };
    let payload = registry
        .send_command(
            node,
            traceparent,
            command::Op::Logs(proto::FetchLogs {
                // The uid and not the name: the node has never heard of the
                // name, and the uid is the identity that survives the hop.
                id: vm.metadata.uid.clone(),
                lines,
            }),
        )
        .await?;
    Ok(Logs::From(payload))
}

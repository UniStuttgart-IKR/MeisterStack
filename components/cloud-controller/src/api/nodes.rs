// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! A cluster's nodes, read here and drained here — the one write on this tier that goes down a session instead of into this store.

use super::*;

// --- the nodes of a cluster, read here and drained here ---------------------
//
// Draining and labelling a machine are operation, and operation goes to the
// cloud. Before this there was no counterpart up here at all: an operator
// needed a second profile at a second tier to cordon a node, which is a
// second endpoint, a second credential and a second thing to be wrong about.
//
// Read is a projection of `Cluster.status.nodes` and write is a command down
// the session. Nothing here creates a Node object at this tier and nothing
// here writes into `status.nodes`: intent travels down, evidence travels up,
// and that is the rule of the whole stack rather than a detail of this route.

/// One reported node, in the envelope the `Node` kind wears one tier down.
///
/// The stored `NodeSummary` is flat because it is a report, and this is what
/// makes it an API object: spec is what an operator decided and status is
/// what the agent said, exactly as the Node object at the cluster splits
/// them. So one `meister node ls` renders both endpoints and `-o json` reads
/// the same at either — which is the whole point of there being one CLI.
///
/// What it does not carry is a uid, a resourceVersion or a heartbeat. It is
/// evidence, and evidence has no version to compare against; a write goes
/// down the session as intent, never as a PUT of this document.
///
/// `spec.drain` travels because it is what an operator asked for from HERE.
/// It was missing (chaos B-C3): a `node drain` sent from the cloud landed,
/// the cluster carried it out, and the cloud's own document of that node did
/// not say so — so `node ls` up here showed no drain column at all and the
/// person who started the drain had to go one tier down to see it.
///
/// `status.draining` is the evidence half beside it — how many guests have
/// left, how many are still going, what is staying and why. It travels on
/// `proto::NodeReport` and lands in `NodeSummary`; here it is written only
/// when there is one, so the document of a machine nobody is emptying reads
/// exactly as it always did. The CLI needs nothing for it: `cluster.rs::
/// node_row` already renders this field for the tier below, and the two
/// documents are meant to read alike.
pub(super) fn as_node_object(n: &controller_api::NodeSummary) -> serde_json::Value {
    let mut object = json!({
        "apiVersion": API_VERSION,
        "kind": "Node",
        "metadata": { "name": n.name },
        // `accepts` beside the other three: an operator who may SET a
        // machine's classes from here has to be able to read them back from
        // here, or the verb is a write into the dark. Written only when the
        // machine names any, so the document of one that takes everything —
        // which is nearly all of them — reads exactly as it always did.
        "spec": { "schedulable": n.schedulable, "drain": n.drain, "labels": n.labels },
        "status": {
            "ready": n.ready,
            "vms": n.vms,
            "capacity": {
                "vcpus": n.vcpus,
                "memMib": n.mem_mib,
                "capabilities": n.capabilities,
            },
        },
    });
    // What the machine says is wrong with itself, and absent when it says
    // nothing — the same omission the `Node` object one tier down makes with
    // `skip_serializing_if`. The two documents have to read alike; that is
    // the whole reason this function exists.
    if !n.conditions.is_empty()
        && let Ok(conditions) = serde_json::to_value(&n.conditions)
    {
        object["status"]["conditions"] = conditions;
    }
    // And what a drain of this machine has done, when one is running. Absent
    // otherwise — which is the same omission the `Node` object one tier down
    // makes, and the reason a `node ls` up here grows a drain column exactly
    // when one down there would.
    if !n.accepts.is_empty() {
        object["spec"]["accepts"] = json!(n.accepts);
    }
    if let Some(draining) = &n.draining
        && let Ok(draining) = serde_json::to_value(draining)
    {
        object["status"]["draining"] = draining;
    }
    object
}

/// The nodes of one cluster, as it last reported them.
pub(super) async fn list_cluster_nodes(
    State(st): State<ApiState>,
    Path(cluster): Path<String>,
    axum::extract::Query(q): axum::extract::Query<controller_api::ListQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let selector = controller_api::Selector::parse(q.label_selector.as_deref())?;
    let c: Cluster = st.store.get(&cluster).await?;
    // Against `spec.labels`, which is where a node's labels live and what a
    // vm's nodeSelector selects against — the same thing the operator who
    // wrote them was thinking of.
    let items: Vec<serde_json::Value> = c
        .status
        .nodes
        .iter()
        .filter(|n| selector.selects(&n.labels))
        .map(as_node_object)
        .collect();
    Ok(Json(json!({
        "apiVersion": API_VERSION,
        "kind": "NodeList",
        "items": items,
    })))
}

/// One of them. 404 when the cluster has never named it — which is also what
/// a node that has left looks like, and the two are the same sentence at this
/// distance.
pub(super) async fn get_cluster_node(
    State(st): State<ApiState>,
    Path((cluster, node)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let c: Cluster = st.store.get(&cluster).await?;
    c.status
        .nodes
        .iter()
        .find(|n| n.name == node)
        .map(|n| Json(as_node_object(n)))
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::NOT_FOUND,
                "NotFound",
                format!("cluster {cluster} reports no node {node}"),
            )
        })
}

/// What a merge patch on a node is allowed to say up here.
///
/// Four fields, and deliberately only four: `schedulable` is the cordon,
/// `drain` empties the machine, `labels` is what a vm's nodeSelector selects
/// against, and `accepts` is what the machine takes. Everything else on a
/// node is what the agent reported, and there is no writing that from
/// anywhere.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NodePatch {
    #[serde(default)]
    spec: NodeSpecPatch,
}

#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NodeSpecPatch {
    #[serde(default)]
    schedulable: Option<bool>,
    /// The drain, beside the cordon and not folded into it: `node drain`
    /// from the cloud is this field, and it reaches the cluster's own object
    /// through the same one command a label does.
    #[serde(default)]
    drain: Option<bool>,
    /// A value sets, `null` removes — RFC 7386 on the two keys this route
    /// has. `Option<Option<String>>` is what tells "said nothing about it"
    /// from "said null", and that difference is the whole format.
    #[serde(default)]
    labels: Option<std::collections::BTreeMap<String, Option<String>>>,
    /// The workload classes this machine takes, `NodeSpec.accepts`. A list
    /// REPLACES — the verb is "this machine takes these and nothing else" —
    /// and the empty list takes the restriction off again.
    ///
    /// `Option<Vec<_>>` for the reason the two flags above are `Option`: a
    /// patch that says nothing about the classes must leave them alone, and
    /// on this route that is the ordinary case.
    #[serde(default)]
    accepts: Option<Vec<String>>,
}

impl NodeSpecPatch {
    /// Does this patch ask for anything at all?
    ///
    /// A question with one place to be answered, so that a field added above
    /// and forgotten here is one mistake and not two. It was already made
    /// once: `drain` arrived beside `schedulable`, `node_update` acted on it,
    /// and this question went on being asked about two fields out of three —
    /// so `meister node drain` at the cloud, the one command this route
    /// exists for, was refused with a sentence that did not name the word.
    fn is_empty(&self) -> bool {
        self.schedulable.is_none()
            && self.drain.is_none()
            && self.labels.is_none()
            && self.accepts.is_none()
    }
}

/// Drain or label one node of one cluster.
///
/// 202 and not 200, and the whole design is in that number: the cloud sends
/// the command, the cluster applies it to its own object, and the evidence
/// comes back with the next status a moment later. The body is the entry as
/// it WILL look — what was asked for, applied to what is known — so that a
/// script has something to read and a person sees what they asked for. The
/// next `node ls` is where it becomes true.
pub(super) async fn patch_cluster_node(
    State(st): State<ApiState>,
    Path((cluster, node)): Path<(String, String)>,
    dry: controller_api::DryRun,
    headers: axum::http::HeaderMap,
    Json(patch): Json<serde_json::Value>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let original = patch.clone();
    let patch: NodePatch = serde_json::from_value(patch).map_err(|e| {
        invalid(format!(
            "a node patch may set spec.schedulable, spec.drain, spec.labels and \
             spec.accepts: {e}"
        ))
    })?;
    if patch.spec.is_empty() {
        return Err(invalid(
            "the patch says nothing; set spec.schedulable, spec.drain, spec.labels or \
             spec.accepts",
        ));
    }

    let c: Cluster = st.store.get(&cluster).await?;
    let Some(entry) = c.status.nodes.iter().find(|n| n.name == node).cloned() else {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "NotFound",
            format!("cluster {cluster} reports no node {node}"),
        ));
    };
    let (command, entry) = node_update(&node, patch, entry);
    // Nothing goes down the session for a preview. `entry` is already "the
    // node as it will read", which is what this route answers with anyway —
    // see the doc above — so the preview is that same answer with the mark on
    // it and no command sent.
    if dry.requested() {
        let mut object = as_node_object(&entry);
        object["metadata"]["annotations"] =
            serde_json::json!({ controller_api::ANNOTATION_DRY_RUN: "true" });
        return Ok((StatusCode::ACCEPTED, Json(object)));
    }

    // Which replica can send it. This write is the only one at this tier that
    // does not go into the shared store: it travels down the cluster's gRPC
    // session, and a cluster dials ONE cloud replica — so two of every three
    // `node cordon`, `node drain` and `node label` calls used to answer 503
    // "no active session", and the client had to GUESS which replica to ask.
    // The uncordon after the mini-chaos run went through exactly one of the
    // three.
    //
    // The same forward `vm logs` takes, and deliberately the same one: two
    // ends of one idea in two places is how a header name, a timeout and a
    // loop rule start disagreeing. What differs is that a write has to carry
    // its body and its ANSWER back whole — a 404 from the sibling is a 404,
    // not the 503 a read collapses everything into.
    match controller_api::forward::holder(
        super::vms::ABOUT,
        st.sessions.holds(&cluster),
        c.status.session_endpoint.as_deref(),
        headers.contains_key(controller_api::forward::FORWARDED),
    ) {
        controller_api::forward::Holder::Here => {}
        controller_api::forward::Holder::Sibling(endpoint) => {
            info!(node = %node, cluster, %endpoint,
                  "forwarding a node patch to the replica that holds the cluster session");
            let path = format!("/apis/meister.io/v1/clusters/{cluster}/nodes/{node}");
            let body = serde_json::to_vec(&original)
                .map_err(|e| invalid(format!("re-encoding the patch: {e}")))?;
            return match controller_api::forward::relay(
                &st.sibling,
                &endpoint,
                axum::http::Method::PATCH,
                &path,
                body.into(),
            )
            .await
            {
                Ok(answer) => forwarded_answer(&endpoint, answer),
                Err(e) => Err(ApiError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Unavailable",
                    format!("{e:#}"),
                )),
            };
        }
        controller_api::forward::Holder::Nowhere(why) => {
            return Err(ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "Unavailable",
                why,
            ));
        }
    }

    match st
        .sessions
        .send_command(&cluster, "", cloud_command::Op::UpdateNode(command))
        .await
    {
        // Accepted, not done: the object one tier down has changed and this
        // cloud's copy of it has not. It will with the next status.
        Ok(controller_api::Ack::Acked(_)) => {
            Ok((StatusCode::ACCEPTED, Json(as_node_object(&entry))))
        }
        // The cluster's own refusal, in its own words — no such node, a lost
        // compare-and-swap, or a node nobody could reach. See `refused`.
        Ok(controller_api::Ack::Rejected(refusal)) => Err(refused(refusal)),
        // Reaching the cluster failed. Same sentence `vm_logs` gives, because
        // it is the same fact: the party that holds the answer is out of
        // reach right now and a caller that retries is right.
        Err(e) => Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "Unavailable",
            format!("{e:#}"),
        )),
    }
}

/// The sibling's answer, as this replica's own.
///
/// The status travels: a 404 for a node the cluster does not report is a 404
/// wherever it was decided, and turning it into the 503 a read collapses
/// everything into would tell a client to retry something that will never
/// work. The body travels unopened for the reason `json_passthrough` gives —
/// two tiers of deserialise-and-reserialise are two chances to change what
/// the other replica said.
pub(super) fn forwarded_answer(
    endpoint: &str,
    answer: controller_api::forward::Answer,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let body: serde_json::Value = serde_json::from_slice(&answer.body).map_err(|e| {
        ApiError::new(
            StatusCode::BAD_GATEWAY,
            "Unavailable",
            format!("the replica at {endpoint} answered something that is not json: {e}"),
        )
    })?;
    Ok((answer.status, Json(body)))
}

/// The patch, turned into the one command that carries it down and into the
/// entry as it will read afterwards.
///
/// Its own function because it is the only part of the route with a decision
/// in it, and the decision — a label with `null` becomes a `remove_labels`
/// entry — is worth a test that does not need a session, a store or a second
/// process.
pub(super) fn node_update(
    node: &str,
    patch: NodePatch,
    mut entry: controller_api::NodeSummary,
) -> (proto::UpdateNode, controller_api::NodeSummary) {
    let mut command = proto::UpdateNode {
        name: node.to_string(),
        schedulable: patch.spec.schedulable,
        drain: patch.spec.drain,
        labels: Default::default(),
        remove_labels: Vec::new(),
        // A list replaces and absent leaves alone, which is exactly what the
        // submessage says: `None` here is no instruction at all.
        accepts: patch
            .spec
            .accepts
            .clone()
            .map(|classes| proto::AcceptsUpdate { classes }),
    };
    if let Some(schedulable) = patch.spec.schedulable {
        entry.schedulable = schedulable;
    }
    if let Some(drain) = patch.spec.drain {
        entry.drain = drain;
    }
    if let Some(classes) = &patch.spec.accepts {
        entry.accepts = classes.clone();
    }
    for (key, value) in patch.spec.labels.unwrap_or_default() {
        match value {
            Some(value) => {
                entry.labels.insert(key.clone(), value.clone());
                command.labels.insert(key, value);
            }
            None => {
                entry.labels.remove(&key);
                command.remove_labels.push(key);
            }
        }
    }
    (command, entry)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// D2, the write half: what the sibling said comes back as it stands.
    ///
    /// A node patch at this tier is the one write that cannot be served by
    /// the replica that was asked — it goes down the cluster's gRPC session,
    /// and one replica holds that. So the asked replica forwards, and the
    /// answer has to survive the hop unchanged: a 404 for a node the cluster
    /// does not report is a 404 wherever it was decided, and collapsing it
    /// into the 503 a read produces would tell a client to retry something
    /// that will never work.
    #[test]
    fn a_forwarded_node_patch_answers_with_what_the_sibling_said() {
        let accepted = controller_api::forward::Answer {
            status: StatusCode::ACCEPTED,
            body: br#"{"kind":"Node","metadata":{"name":"agent-1a"}}"#.to_vec().into(),
        };
        let (status, Json(body)) = match forwarded_answer("10.128.1.103:3000", accepted) {
            Ok(pair) => pair,
            Err(e) => panic!("a well-formed answer: {}", e.message()),
        };
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(body["metadata"]["name"], "agent-1a");

        // The refusal, with its own status and its own sentence.
        let refused = controller_api::forward::Answer {
            status: StatusCode::NOT_FOUND,
            body: br#"{"kind":"Status","reason":"NotFound","message":"cluster cluster-1 reports no node manacor"}"#
                .to_vec()
                .into(),
        };
        let (status, Json(body)) = match forwarded_answer("10.128.1.103:3000", refused) {
            Ok(pair) => pair,
            Err(e) => panic!("a refusal is an answer: {}", e.message()),
        };
        assert_eq!(status, StatusCode::NOT_FOUND, "not collapsed into a 503");
        assert_eq!(body["message"], "cluster cluster-1 reports no node manacor");

        // Something that is not this API at all on the other end is a 502 and
        // says which replica: passing the bytes through would put a proxy's
        // html in front of somebody reading a node.
        let junk = controller_api::forward::Answer {
            status: StatusCode::OK,
            body: b"<html>gateway</html>".to_vec().into(),
        };
        let Err(e) = forwarded_answer("10.128.1.103:3000", junk) else {
            panic!("html is not this api");
        };
        assert_eq!(e.status(), StatusCode::BAD_GATEWAY);
        assert!(e.message().contains("10.128.1.103:3000"), "{}", e.message());
    }

    /// Cordon and drain are two statements and travel as two fields.
    ///
    /// Saying nothing about one of them must not say `false` about it: a
    /// `node drain` from the cloud has to be able to leave an operator's
    /// cordon exactly as they set it, and an `undrain` has to give back the
    /// schedulability they asked for rather than one this route invented.
    #[test]
    fn draining_a_node_from_the_cloud_says_nothing_about_its_cordon() {
        let entry = controller_api::NodeSummary {
            name: "agent-1".into(),
            ready: true,
            schedulable: false,
            drain: false,
            accepts: Vec::new(),
            labels: Default::default(),
            vcpus: 8,
            mem_mib: 8192,
            capabilities: Vec::new(),
            vms: 2,
            conditions: Vec::new(),
            draining: None,
        };

        let patch: NodePatch =
            serde_json::from_value(json!({ "spec": { "drain": true } })).unwrap();
        let (command, next) = node_update("agent-1", patch, entry.clone());
        assert_eq!(command.drain, Some(true));
        assert_eq!(
            command.schedulable, None,
            "the cordon was not mentioned, so nothing about it is sent"
        );
        assert!(next.drain);
        assert!(
            !next.schedulable,
            "and the cordon this node already had is still there"
        );

        // The other way round, which is what `node cordon` has always been.
        let patch: NodePatch =
            serde_json::from_value(json!({ "spec": { "schedulable": true } })).unwrap();
        let (command, next) = node_update("agent-1", patch, entry);
        assert_eq!(command.drain, None, "a cordon says nothing about a drain");
        assert_eq!(command.schedulable, Some(true));
        assert!(next.schedulable);
    }

    /// The one decision in the node PATCH route: a label with `null` is a
    /// removal, and the entry that comes back is what the next status will
    /// say — which is why the answer is 202 and not 200.
    #[test]
    fn a_node_patch_becomes_one_command_and_the_entry_it_will_produce() {
        let entry = controller_api::NodeSummary {
            name: "manacor".into(),
            ready: true,
            schedulable: true,
            drain: false,
            accepts: Vec::new(),
            labels: [
                ("zone".to_string(), "a".to_string()),
                ("disk".to_string(), "nvme".to_string()),
            ]
            .into_iter()
            .collect(),
            vcpus: 32,
            mem_mib: 65_536,
            capabilities: vec!["nvrm/4q".into()],
            vms: 2,
            conditions: Vec::new(),
            draining: None,
        };
        let patch: NodePatch = serde_json::from_value(json!({
            "spec": { "schedulable": false, "labels": { "gpu": "a100", "zone": null } }
        }))
        .unwrap();

        let (command, next) = node_update("manacor", patch, entry.clone());
        assert_eq!(command.name, "manacor");
        assert_eq!(command.schedulable, Some(false));
        assert_eq!(command.labels["gpu"], "a100");
        assert_eq!(command.remove_labels, vec!["zone".to_string()]);
        // What the caller is shown: what was asked for, applied to what is
        // known. The cluster is what makes it true.
        assert!(!next.schedulable);
        assert_eq!(next.labels["gpu"], "a100");
        assert_eq!(next.labels["disk"], "nvme", "and the rest stayed");
        assert!(!next.labels.contains_key("zone"));
        // Nothing the agent reported is touched by any of this.
        assert_eq!((next.vcpus, next.mem_mib, next.vms), (32, 65_536, 2));

        // A cordon on its own names no labels at all.
        let cordon: NodePatch =
            serde_json::from_value(json!({"spec": {"schedulable": false}})).unwrap();
        let (command, _) = node_update("manacor", cordon, entry);
        assert!(command.labels.is_empty() && command.remove_labels.is_empty());
    }

    /// What an operator asked for from HERE is readable from here (chaos
    /// B-C3).
    ///
    /// `node drain` at the cloud landed, the cluster carried it out, and the
    /// cloud's own document of that node said nothing about it: `spec.drain`
    /// stopped at `NodeSummary` and never reached the object, so `node ls` up
    /// here had no drain column at all and the person who started the drain
    /// had to open a second profile at a second tier to see it.
    ///
    /// The evidence half — `status.draining`, and `movedTotal` in it — is
    /// here too now: it travels on `proto::NodeReport.draining`, and the
    /// document says it exactly when there is a drain to say it about.
    #[test]
    fn the_clouds_document_of_a_node_says_whether_it_is_being_drained() {
        let entry = controller_api::NodeSummary {
            name: "manacor".into(),
            ready: true,
            schedulable: false,
            drain: true,
            accepts: Vec::new(),
            labels: Default::default(),
            vcpus: 32,
            mem_mib: 65_536,
            capabilities: Vec::new(),
            vms: 2,
            conditions: Vec::new(),
            draining: Some(controller_api::Draining {
                leaving: 1,
                leaving_vms: vec!["web-2".into()],
                moved_total: 4,
                staying: 1,
                complete: false,
                reasons: vec![controller_api::StayingVm {
                    vm: "db-1".into(),
                    reason: "evacuation-never".into(),
                    message: "its owner said evacuation: never".into(),
                }],
            }),
        };
        let object = as_node_object(&entry);
        assert_eq!(object["spec"]["drain"], json!(true));
        // And the cordon beside it, because the two are separate statements
        // and a document that ran them together would be a document a client
        // cannot undo one of.
        assert_eq!(object["spec"]["schedulable"], json!(false));

        // The evidence, in the spelling `cluster.rs::node_row` already reads
        // for the tier below — the two documents are meant to read alike.
        let draining = &object["status"]["draining"];
        assert_eq!(draining["movedTotal"], json!(4));
        assert_eq!(draining["leaving"], json!(1));
        assert_eq!(draining["leavingVms"], json!(["web-2"]));
        assert_eq!(draining["staying"], json!(1));
        assert_eq!(draining["complete"], json!(false));
        assert_eq!(draining["reasons"][0]["vm"], json!("db-1"));
        assert_eq!(draining["reasons"][0]["reason"], json!("evacuation-never"));

        // A machine that takes everything says nothing about its classes, so
        // its document is byte for byte the one it always was.
        assert!(
            object["spec"].get("accepts").is_none(),
            "{}",
            object["spec"]
        );
        // And one that was told otherwise reads it back where it was set —
        // an operator who may write a field from here has to be able to see
        // it from here.
        let fussy = controller_api::NodeSummary {
            accepts: vec!["router".into()],
            ..entry.clone()
        };
        assert_eq!(as_node_object(&fussy)["spec"]["accepts"], json!(["router"]));

        let quiet = controller_api::NodeSummary {
            drain: false,
            accepts: Vec::new(),
            schedulable: true,
            draining: None,
            ..entry
        };
        assert_eq!(as_node_object(&quiet)["spec"]["drain"], json!(false));

        // And a machine nobody is emptying says nothing rather than a block
        // of zeroes — which is also what a cluster from before the field
        // sends, and the reason `node ls` up here grows a drain column
        // exactly when one down there would.
        assert!(as_node_object(&quiet)["status"].get("draining").is_none());
    }

    /// A body that names anything else is refused rather than half-applied:
    /// everything on a node but these two fields is what the agent reported,
    /// and there is no writing that from anywhere.
    #[test]
    fn a_node_patch_may_say_three_things_and_no_others() {
        for body in [
            json!({ "spec": { "ready": true } }),
            json!({ "status": { "ready": true } }),
            json!({ "spec": { "vcpus": 64 } }),
        ] {
            assert!(
                serde_json::from_value::<NodePatch>(body.clone()).is_err(),
                "{body} should not parse as a node patch"
            );
        }
        assert!(serde_json::from_value::<NodePatch>(json!({"spec": {"labels": {}}})).is_ok());

        // And each of the three is a patch that SAYS something. `drain` is
        // the one this missed: `meister node drain` sends exactly
        // `{"spec":{"drain":true}}` and nothing else, so the route refused
        // the only command it has — seen at the local stack, 422 with a
        // sentence that named the other two fields.
        for body in [
            json!({ "spec": { "drain": true } }),
            json!({ "spec": { "schedulable": false } }),
            json!({ "spec": { "labels": { "zone": "a" } } }),
        ] {
            let patch: NodePatch = serde_json::from_value(body.clone()).unwrap();
            assert!(!patch.spec.is_empty(), "{body} asks for something");
        }
        let nothing: NodePatch = serde_json::from_value(json!({})).unwrap();
        assert!(
            nothing.spec.is_empty(),
            "and an empty body asks for nothing"
        );
    }

    /// The guard in front of the route, and it needs no new code: `classify`
    /// already reads `clusters/{c}/nodes/{n}` as the `clusters` resource with
    /// a `nodes` subresource, and the permission table makes that Viewer to
    /// read and Operator to write.
    #[test]
    fn draining_a_node_from_here_is_an_operators_act_and_reading_one_is_a_viewers() {
        let read =
            controller_api::classify("GET", "/apis/meister.io/v1/clusters/c1/nodes").unwrap();
        let write =
            controller_api::classify("PATCH", "/apis/meister.io/v1/clusters/c1/nodes/manacor")
                .unwrap();
        assert_eq!((read.resource, read.verb), ("clusters", Verb::Read));
        assert_eq!(
            (write.resource, write.subresource, write.verb),
            ("clusters", Some("nodes"), Verb::Write)
        );

        let who =
            |role: Role| controller_api::Identity::new("someone", vec![role.group().to_string()]);
        for (role, may_write) in [
            (Role::Viewer, false),
            (Role::Member, false),
            (Role::Operator, true),
            (Role::Admin, true),
        ] {
            assert!(
                controller_api::permits(&who(role), Some(role), None, &read, None),
                "{} reads",
                role.as_str()
            );
            assert_eq!(
                controller_api::permits(&who(role), Some(role), None, &write, None),
                may_write,
                "{} writes",
                role.as_str()
            );
        }
    }

    /// A refusal that crossed a session keeps the word the tier that MET the
    /// failure chose.
    ///
    /// The case this exists for, measured in the lab: with three cloud and
    /// four cluster replicas, a console read that lands on a replica whose
    /// cluster cannot reach the node used to answer `409 Conflict` — for a
    /// fact that is not a disagreement and that a caller should simply ask
    /// again. Now it answers 503, with the cluster's own sentence.
    #[test]
    fn a_refusal_keeps_the_reason_the_other_tier_gave_it() {
        let map = |reason: &str| {
            let e = refused(controller_api::Refusal::new("the sentence", reason));
            (e.status(), e.reason())
        };

        assert_eq!(
            map("Unavailable"),
            (axum::http::StatusCode::SERVICE_UNAVAILABLE, "Unavailable"),
            "nobody could be reached is not a conflict"
        );
        assert_eq!(
            map("Timeout"),
            (axum::http::StatusCode::SERVICE_UNAVAILABLE, "Timeout")
        );
        assert_eq!(
            map("NotFound"),
            (axum::http::StatusCode::NOT_FOUND, "NotFound")
        );
        assert_eq!(
            map("Conflict"),
            (axum::http::StatusCode::CONFLICT, "Conflict")
        );

        // The compatibility case, and the one that matters most: a peer that
        // names no reason means what a bare rejection always meant. Every
        // agent today is such a peer, and so is every cluster running a
        // binary from before this field existed.
        assert_eq!(
            map(""),
            (axum::http::StatusCode::CONFLICT, "Conflict"),
            "silence keeps the old meaning"
        );
        // And a word this tier has never heard of does not become a guess.
        assert_eq!(
            map("SomethingNewer"),
            (axum::http::StatusCode::CONFLICT, "Conflict")
        );

        // The sentence is the other tier's throughout.
        assert_eq!(
            refused(controller_api::Refusal::new("the sentence", "Unavailable")).message(),
            "the sentence"
        );
    }
}

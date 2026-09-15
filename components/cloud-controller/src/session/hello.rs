// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Hello and goodbye: the cluster that dials in, and the last replica of it
//! that hangs up.
//!
//! Hello is the one message that creates a `Cluster` object, so it is also
//! what keeps the first status from writing into nothing; `closed` is its
//! mirror and is careful about which of the several replicas of one cluster
//! it is saying goodbye to. Verbatim out of `session.rs`.

use super::*;

/// Hello: the cluster exists from now on. Creating on first sight is what makes
/// the inventory survive the cluster — one that is down is disconnected, not
/// absent — and it is also what keeps the first status from writing into
/// nothing, because `mutate` does not create.
pub(super) async fn ingest_hello(
    store: &EtcdStore,
    hello: &ClusterHello,
    advertise: Option<&str>,
) -> anyhow::Result<()> {
    let name = hello.cluster_name.as_str();
    if matches!(
        store.get::<Cluster>(name).await,
        Err(StoreError::NotFound(_))
    ) {
        match store
            .create(&Cluster::declare(name, ClusterSpec::default()))
            .await
        {
            // Two sessions for one cluster can race here; either object will do.
            Ok(_) | Err(StoreError::AlreadyExists(_)) => {}
            Err(e) => return Err(e.into()),
        }
    }
    let version = hello.version.clone();
    // A Hello is a beat: it is the first thing a cluster says on a new
    // session, and a lease that waited for the first status report would read
    // as expired for up to ten seconds after connecting (D-C7).
    store.beat::<Cluster>(name, Utc::now()).await?;
    store
        .mutate::<Cluster, _>(name, |c| {
            c.status.connected = true;
            c.status.version = Some(version.clone());
            // This cluster dialled THIS replica, so this replica is the only
            // one that can ask it anything. Writing where it can be reached
            // is what lets a sibling forward a console instead of refusing.
            c.status.session_endpoint = advertise.map(str::to_string);
        })
        .await?;
    Ok(())
}

impl Connection {
    /// The cluster exists from now on, under the name its certificate allows
    /// it to claim.
    pub(super) async fn hello(&self, live: &mut Live, hello: ClusterHello) -> Step {
        // The certificate said who dialled; the hello says which cluster it
        // claims to be. One cluster's key must not let it speak for another's
        // VMs.
        if let Err(e) =
            controller_api::grpc::check_session_identity(&self.who, "cluster", &hello.cluster_name)
        {
            // Error, not warn: a cluster whose certificate does not match the
            // name it claims will redial with the same certificate for ever.
            // No reconnect repairs that; only a person re-issuing it does.
            error!(cluster = %hello.cluster_name, error = format!("{e:#}"),
                   "refusing the session");
            let _ = self.tx.send(Err(e)).await;
            return Step::Stop;
        }
        info!(cluster = %hello.cluster_name, version = %hello.version, "cluster connected");
        if let Err(e) = ingest_hello(&self.store, &hello, self.advertise.as_deref()).await {
            warn!(cluster = %hello.cluster_name, error = format!("{e:#}"),
                  "recording the cluster failed");
        }
        // Once per session, so a transition by construction — see the twin
        // one tier down. A cluster that reconnects in a loop aggregates into
        // one object with a count.
        events::record(
            &self.store,
            Happening {
                kind: Cluster::KIND,
                name: &hello.cluster_name,
                uid: "",
                reason: events::reason::PEER_READY,
                message: format!("cluster {} connected", hello.version),
                event_type: EventType::Normal,
                tenant: None,
            },
        )
        .await;
        live.id = Some(
            self.registry
                .open(live.id, &hello.cluster_name, &self.tx, Utc::now()),
        );
        live.cluster = Some(hello.cluster_name);
        Step::Continue
    }

    /// The stream is over. Only the last replica of a cluster leaving means
    /// the cluster is gone; a reconnect that already replaced us, or a sibling
    /// still dialled in, keeps its own session and its readiness.
    pub(super) async fn closed(&self, live: &Live) {
        let Some(id) = live.id else { return };
        match self.registry.close(id) {
            Some(name) => {
                info!(cluster = %name, "cluster disconnected");
                // Forgotten with the session that said it: skipping a send on
                // the strength of a departed cluster's word would be the one
                // way this optimisation could lose a secret.
                self.registry.secrets.forget(&name);
                let result = self
                    .store
                    .mutate::<Cluster, _>(&name, |c| c.status.connected = false)
                    .await;
                if let Err(e) = result {
                    warn!(cluster = %name, error = format!("{e:#}"),
                          "marking the cluster down failed");
                }
            }
            None => debug!(
                cluster = live.cluster.as_deref().unwrap_or("?"),
                "session closed, another of this cluster is live"
            ),
        }
    }
}

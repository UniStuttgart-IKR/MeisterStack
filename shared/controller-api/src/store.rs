// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! etcd-backed object store. Keys are `<prefix>/registry/<resource>/<name>`,
//! values the JSON of the whole object; `metadata.resource_version` carries
//! the etcd mod_revision out and is compared on update (CAS). The prefix is
//! configuration — an all-in-one box shares one etcd under /cloud and
//! /cluster, real separation is a different endpoint. No controller ever
//! reads a foreign prefix (the Oakestra rule).

use std::future::Future;
use std::time::Duration;

use etcd_client::{
    Client, Compare, CompareOp, ConnectOptions, DeleteOptions, Event, EventType, GetOptions,
    PutOptions, Txn, TxnOp, TxnResponse, WatchOptions,
};
use tracing::{error, info, warn};

use crate::object::{NameShape, Resource, StoredObject};

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("object not found: {0}")]
    NotFound(String),
    #[error("object already exists: {0}")]
    AlreadyExists(String),
    /// The name is taken by an object that is on its way out: deleted, and
    /// waiting for a finalizer. Its own variant and not `AlreadyExists`,
    /// because the two ask different things of the caller — one means "pick
    /// another name" and this one means "wait a moment". Both are 409, and
    /// telling them apart is the whole point.
    #[error("object is being deleted: {0}")]
    Terminating(String),
    /// Two writers wanted the same thing and one of them lost. The message is
    /// the WHOLE sentence and not a subject the variant decorates: a lost CAS
    /// on a resourceVersion and a floating address somebody already holds are
    /// both 409s and read nothing alike, and the one that reaches an operator
    /// is whichever the server wrote.
    #[error("{0}")]
    Conflict(String),
    /// The request cannot be carried out as written. The message is the whole
    /// sentence, for the same reason `Conflict`'s is: a malformed object and a
    /// quota that is used up are both 422s, both reach an operator's terminal
    /// verbatim, and only one of them is about an object being invalid.
    #[error("{0}")]
    Invalid(String),
    #[error("etcd: {0}")]
    Backend(#[from] etcd_client::Error),
    #[error("etcd {0} did not answer within {1:?}")]
    Timeout(&'static str, Duration),
}

pub type Result<T> = std::result::Result<T, StoreError>;

impl StoreError {
    /// One word for the KIND of failure, for the `result` label on
    /// `meister_etcd_errors_total`.
    ///
    /// The variant and never the message: the messages name keys, object
    /// names and whole sentences, and a label built from one of those is the
    /// unbounded label that takes a Prometheus down. Six words, one per
    /// variant, and adding a variant is a compile error here.
    pub fn metric_result(&self) -> &'static str {
        match self {
            StoreError::NotFound(_) => "not-found",
            StoreError::AlreadyExists(_) => "already-exists",
            StoreError::Terminating(_) => "terminating",
            StoreError::Conflict(_) => "conflict",
            StoreError::Invalid(_) => "invalid",
            StoreError::Backend(_) => "backend",
            StoreError::Timeout(..) => "timeout",
        }
    }
}

pub struct EtcdStore {
    client: Client,
    prefix: String,
}

/// How long one etcd request may take before the caller stops waiting.
///
/// Not a network setting but a liveness one. An etcd that has lost quorum
/// accepts a request and answers nothing at all, and a caller that waits for
/// that answer for ever is a caller that never runs its next pass — the
/// reconcile pass on its 5s tick, the session ingest writing a heartbeat, the
/// REST handler somebody is waiting on.
///
/// Requests no longer queue behind one another (see `EtcdStore::handle`), so
/// one that hangs costs its own caller and nobody else. The bound is what
/// turns that cost into an error the caller can act on rather than a task
/// that is simply gone.
///
/// Five seconds is one tick. A pass that skips a tick and warns is a
/// controller that is behind; a pass that never returns is one that is gone,
/// and the difference is which of those a partition looks like from outside.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// The same bound on getting a connection in the first place, and the reason
/// is the one from `proto::DIAL_TIMEOUT`: a blackholed endpoint costs the
/// kernel's `tcp_syn_retries` — about two minutes — before it gives up, and
/// `main` has a retry loop that cannot retry while it is still waiting.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// Bound one request. `what` names the operation in the error, because a
/// timeout that only says "etcd" tells an operator nothing about which of
/// several concurrent callers is the one that is stuck.
///
/// Watches are deliberately NOT wrapped, and the etcd client's own
/// `with_timeout` is deliberately not used: both bound a whole response, and
/// a watch is a stream that is SUPPOSED to stay silent for hours. Setting it
/// there would tear the watch down every five seconds and leave the tick
/// carrying the whole reconciler.
async fn timed<T, E>(
    what: &'static str,
    fut: impl Future<Output = std::result::Result<T, E>>,
) -> Result<T>
where
    StoreError: From<E>,
{
    let clock = telemetry::metrics::Timer::start();
    let outcome = match tokio::time::timeout(REQUEST_TIMEOUT, fut).await {
        Ok(result) => result.map_err(StoreError::from),
        Err(_) => Err(StoreError::Timeout(what, REQUEST_TIMEOUT)),
    };
    // Every store operation in the process passes through here, which is what
    // makes this the one place the latency and the failure rate can be
    // measured without an argument about which call sites were instrumented.
    telemetry::metrics::etcd().observe(what, clock.seconds());
    if let Err(e) = &outcome {
        telemetry::metrics::etcd().failed(what, e.metric_result());
    }
    outcome
}

/// Where this process is in the store's history, from whatever answer just
/// came back. Every etcd response carries the revision it was served at, so
/// this costs nothing beyond the read — and a controller whose observed
/// revision stops moving while another replica's climbs is a controller that
/// has been partitioned off, which is not visible from anything else here.
fn observe_revision(header: Option<&etcd_client::ResponseHeader>) {
    if let Some(header) = header {
        telemetry::metrics::etcd().saw_revision(header.revision());
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WatchEvent {
    Put,
    Delete,
}

impl EtcdStore {
    pub async fn connect(endpoints: &[String], prefix: &str) -> Result<Self> {
        let options = ConnectOptions::new().with_connect_timeout(CONNECT_TIMEOUT);
        let client = Client::connect(endpoints, Some(options)).await?;
        Ok(Self {
            client,
            prefix: prefix.trim_end_matches('/').to_string(),
        })
    }

    /// A client for ONE request.
    ///
    /// The etcd client's own methods take `&mut self`, which is why this used
    /// to be a `Mutex<Client>` — and a mutex whose guard is held across the
    /// await of a network round trip is not a lock, it is a queue. Every
    /// store operation in the process stood in it: the reconcile pass on its
    /// 5s tick, the session ingest writing a heartbeat, the REST handler
    /// somebody is waiting on. One request that ran into `REQUEST_TIMEOUT`
    /// stopped all of them for five seconds.
    ///
    /// `etcd_client::Client` is `Clone` and a clone is a handle, not a
    /// connection: the sub-clients it holds are tonic clients over one
    /// `tonic::transport::Channel`, which is itself a cheap handle onto the
    /// shared connection pool, and the auth token behind them is one
    /// `Arc<RwLock<_>>` all clones read. So a clone per request costs a few
    /// atomic increments and gives every caller its own `&mut`, which is what
    /// the queue was standing in for. gRPC multiplexes the requests on the
    /// one connection, as it was always going to.
    fn handle(&self) -> Client {
        self.client.clone()
    }

    fn key(&self, resource: &str, name: &str) -> String {
        format!("{}/registry/{}/{}", self.prefix, resource, name)
    }

    fn dir(&self, resource: &str) -> String {
        format!("{}/registry/{}/", self.prefix, resource)
    }

    fn decode<T: StoredObject>(bytes: &[u8], mod_revision: i64) -> Result<T> {
        let mut obj: T = serde_json::from_slice(bytes)
            .map_err(|e| StoreError::Invalid(format!("invalid object: does not parse: {e}")))?;
        obj.metadata_mut().resource_version = mod_revision.to_string();
        Ok(obj)
    }

    /// The bytes that go into etcd, and the one place [`Resource::settle`] is
    /// called from.
    ///
    /// Here rather than in `update` and `create` separately, because "before
    /// the bytes are made" is exactly what the hook has to mean: every write
    /// in this file passes through here, `mutate` included (it writes through
    /// `update`), so there is no path that stores an object the derivation
    /// never saw. A caller that wants the settled object back reads the
    /// return value of the write, which is decoded from these very bytes.
    ///
    /// It costs no clone that was not already being made: the copy exists
    /// anyway, to keep `resourceVersion` out of the store.
    fn encode<T: Resource>(obj: &T, now: chrono::DateTime<chrono::Utc>) -> Result<Vec<u8>> {
        // resource_version is derived state; never persist it.
        let mut clean = obj.clone();
        clean.metadata_mut().resource_version = String::new();
        clean.settle(now);
        serde_json::to_vec(&clean).map_err(|e| StoreError::Invalid(format!("invalid object: {e}")))
    }

    /// One read against the store, for a readiness probe.
    ///
    /// A key that need not exist, and that is deliberate: what is being asked
    /// is whether the store ANSWERS, not whether it holds anything in
    /// particular. A probe that depended on content would go red the first
    /// time somebody emptied a directory, which is a working control plane
    /// with nothing in it.
    ///
    /// The read goes through `timed` like every other, so it also lands in
    /// the etcd latency and failure metrics — a replica that is flapping
    /// ready shows up there before anybody reads its probe log.
    pub async fn probe(&self) -> Result<()> {
        let key = format!("{}/readyz", self.prefix);
        let resp = timed("probe", self.handle().get(key, None)).await?;
        observe_revision(resp.header());
        Ok(())
    }

    pub async fn get<T: Resource>(&self, name: &str) -> Result<T> {
        let key = self.key(T::RESOURCE, name);
        let resp = timed("get", self.handle().get(key.clone(), None)).await?;
        observe_revision(resp.header());
        let kv = resp.kvs().first().ok_or_else(|| {
            StoreError::NotFound(format!("{resource}/{name}", resource = T::RESOURCE))
        })?;
        Self::decode(kv.value(), kv.mod_revision())
    }

    pub async fn list<T: Resource>(&self) -> Result<Vec<T>> {
        let dir = self.dir(T::RESOURCE);
        let resp = timed(
            "list",
            self.handle()
                .get(dir, Some(GetOptions::new().with_prefix())),
        )
        .await?;
        observe_revision(resp.header());
        let mut out = Vec::with_capacity(resp.kvs().len());
        for kv in resp.kvs() {
            match Self::decode(kv.value(), kv.mod_revision()) {
                Ok(obj) => out.push(obj),
                // Error, not warn: an object the store cannot decode stays
                // invisible to every pass from here on and no retry, reconnect
                // or reconcile repairs it. Only a person editing the key does.
                Err(e) => error!(key = %String::from_utf8_lossy(kv.key()),
                                 error = format!("{e:#}"), "skipping undecodable object"),
            }
        }
        Ok(out)
    }

    /// How many keys the resource prefix actually holds. `list` degrades on
    /// an object it cannot decode — it says so and drops it — which is right
    /// for a reconcile pass and wrong for any caller whose correctness rests
    /// on the list being complete. Those compare against this.
    pub async fn count<T: Resource>(&self) -> Result<usize> {
        let dir = self.dir(T::RESOURCE);
        let opts = GetOptions::new().with_prefix().with_count_only();
        let resp = timed("count", self.handle().get(dir, Some(opts))).await?;
        observe_revision(resp.header());
        Ok(resp.count().max(0) as usize)
    }

    /// The longest a name may be. Not arbitrary: a name reaches a node as
    /// part of a network interface name, and Linux allows fifteen bytes for
    /// one of those. This is the object name and not the interface name — the
    /// drivers derive those and keep their own budget — but a name that can
    /// never fit anywhere downstream is not worth storing.
    const MAX_NAME: usize = 63;

    /// A name is the last segment of an etcd key, a piece of a file name on a
    /// node, and part of an interface name. That is three places downstream,
    /// and the DNS label is the intersection of what all three survive —
    /// Kubernetes' own answer, for the same reason.
    ///
    /// It is not, however, the answer for every resource, because the third
    /// place does not apply to all of them. `NameShape::Dotted` is the same
    /// rule with `.` allowed inside it, for the two resources whose name was
    /// never a word an operator chose: a floating address, and the file name
    /// an image is looked up as. See [`crate::object::NameShape`].
    ///
    /// The lab found what the check before this let past, and each one is a
    /// different kind of trouble: a name with a SPACE (a shell word boundary
    /// on every node that handles it), non-ASCII (`chaos-üml`, which is not
    /// one byte per character anywhere it is counted), uppercase (two objects
    /// that differ only in case are one file on a case-insensitive mount),
    /// 300 characters, and an embedded `..` that it only caught when the
    /// whole name was `..`. None of those is allowed under either shape.
    fn check_name(name: &str, shape: NameShape) -> Result<()> {
        let invalid = |why: &str| {
            Err(StoreError::Invalid(format!(
                "invalid object: metadata.name {name:?} {why}"
            )))
        };
        if name.is_empty() {
            return Err(StoreError::Invalid(
                "invalid object: metadata.name must be set".into(),
            ));
        }
        if name.len() > Self::MAX_NAME {
            return invalid(&format!(
                "is {} bytes; at most {} are allowed",
                name.len(),
                Self::MAX_NAME
            ));
        }
        let dotted = shape == NameShape::Dotted;
        if !name.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || (dotted && b == b'.')
        }) {
            return invalid(if dotted {
                "may hold only lowercase letters, digits, '-' and '.' \
                 (it is one path segment: it becomes an etcd key and a file name)"
            } else {
                "may hold only lowercase letters, digits and '-' \
                 (it is a dns label: it becomes an etcd key, a file name and \
                 part of an interface name)"
            });
        }
        // `..` is the traversal the old check missed, and it stays refused
        // under the wider shape for exactly that reason.
        if dotted && name.contains("..") {
            return invalid("may not hold \"..\"");
        }
        if !name.starts_with(|c: char| c.is_ascii_alphanumeric())
            || !name.ends_with(|c: char| c.is_ascii_alphanumeric())
        {
            return invalid("must start and end with a letter or a digit");
        }
        Ok(())
    }

    /// Create fails if the key exists (like a POST).
    pub async fn create<T: Resource>(&self, obj: &T) -> Result<T> {
        self.create_inner(obj, None).await
    }

    /// Create an object that etcd itself will delete again after `ttl_secs`.
    ///
    /// The one resource that expires — events. A lease is granted for this
    /// object alone and etcd reaps the key when it runs out, so the expiry
    /// needs no sweeper task, no reconcile pass and nobody alive at all: a
    /// control plane that is down for two hours comes back to an event log
    /// that has already tidied itself.
    ///
    /// One grant per created object rather than a shared one per process or
    /// per time bucket. A shared lease would take every event with it when
    /// the process holding it stopped renewing, and a bucketed one would give
    /// the last object of each bucket a shorter life than it was promised.
    /// Objects that expire are rare by construction — see `events`, which
    /// writes one only when something CHANGED — so the extra round trip is
    /// paid about as often as something happens.
    pub async fn create_with_ttl<T: Resource>(&self, obj: &T, ttl_secs: i64) -> Result<T> {
        let lease = timed("lease_grant", self.handle().lease_grant(ttl_secs, None)).await?;
        self.create_inner(obj, Some(lease.id())).await
    }

    async fn create_inner<T: Resource>(&self, obj: &T, lease: Option<i64>) -> Result<T> {
        let name = obj.metadata().name.clone();
        Self::check_name(&name, T::NAME_SHAPE)?;
        // Every object starts at generation 1, and here rather than in the
        // handlers because there are a dozen of those and one of these. What
        // a client sent in the field is not consulted: the count is the
        // server's, or it is worth nothing. See `Metadata::generation`.
        let mut obj = obj.clone();
        obj.metadata_mut().generation = 1;
        let obj = &obj;
        let key = self.key(T::RESOURCE, &name);
        let value = Self::encode(obj, chrono::Utc::now())?;
        let options = lease.map(|id| PutOptions::new().with_lease(id));
        let txn = Txn::new()
            .when(vec![Compare::create_revision(
                key.clone(),
                CompareOp::Equal,
                0,
            )])
            // The put takes the bytes and `written` decodes the result from
            // them, so one of the two gets a copy. One allocation against the
            // read-back round trip it replaces.
            .and_then(vec![TxnOp::put(key.clone(), value.clone(), options)])
            // Read the squatter, but only on the branch where there is one.
            // A create that succeeds pays nothing for this, and a create that
            // fails can then say WHICH kind of taken the name is.
            .or_else(vec![TxnOp::get(key.clone(), None)]);
        let resp = timed("create", self.handle().txn(txn)).await?;
        if !resp.succeeded() {
            let subject = format!("{resource}/{name}", resource = T::RESOURCE);
            return Err(if Self::is_terminating(resp.op_responses()) {
                StoreError::Terminating(subject)
            } else {
                StoreError::AlreadyExists(subject)
            });
        }
        self.written(&name, &value, &resp).await
    }

    /// Does the object that holds this name carry a deletion timestamp?
    ///
    /// Read as JSON and not as `T`: this runs on a failure path, and a
    /// decode that fails there would turn "the name is taken" into "the store
    /// is broken". Anything unreadable is reported as a plain collision,
    /// which is the answer that was given before this existed.
    fn is_terminating(ops: Vec<etcd_client::TxnOpResponse>) -> bool {
        ops.into_iter().any(|op| match op {
            etcd_client::TxnOpResponse::Get(r) => {
                r.kvs().iter().any(|kv| Self::is_deleting(kv.value()))
            }
            _ => false,
        })
    }

    /// The half of the above that can be tested: the etcd response type
    /// cannot be built outside a client, and the decision can.
    fn is_deleting(value: &[u8]) -> bool {
        serde_json::from_slice::<serde_json::Value>(value)
            .ok()
            .and_then(|v| {
                v.get("metadata")?
                    .get("deletionTimestamp")?
                    .as_str()
                    .map(|s| !s.is_empty())
            })
            .unwrap_or(false)
    }

    /// The object as the store now holds it, without asking the store again.
    ///
    /// A successful txn's header revision IS the mod_revision of the key it
    /// just wrote — etcd stamps every response with the revision the request
    /// was applied at, and for a txn that put one key that revision is that
    /// key's. `value` is the byte-for-byte record that landed there. So
    /// decoding our own bytes at that revision is what a `get` would have
    /// returned, one round trip earlier.
    ///
    /// It is also the more correct of the two answers, which is the reason
    /// worth writing down. A read AFTER the write reads whatever is there
    /// NOW: a create or an update that was overwritten a millisecond later
    /// used to hand its caller the OTHER writer's object, under the caller's
    /// own name, with a resourceVersion that is not the one its own write
    /// produced — and an `update` built on that version would then CAS
    /// successfully against a document nobody in this process had ever seen.
    ///
    /// A response without a header is not something etcd sends. If one ever
    /// does arrive, the read it replaced is still there to fall back on.
    async fn written<T: Resource>(
        &self,
        name: &str,
        value: &[u8],
        resp: &TxnResponse,
    ) -> Result<T> {
        observe_revision(resp.header());
        match resp.header() {
            Some(header) => Self::decode(value, header.revision()),
            None => self.get(name).await,
        }
    }

    /// Compare-and-swap on the object's resource_version.
    pub async fn update<T: Resource>(&self, obj: &T) -> Result<T> {
        let name = obj.metadata().name.clone();
        Self::check_name(&name, T::NAME_SHAPE)?;
        let rev: i64 = obj.metadata().resource_version.parse().map_err(|_| {
            StoreError::Invalid(
                "invalid object: metadata.resourceVersion must be set for updates".into(),
            )
        })?;
        let key = self.key(T::RESOURCE, &name);
        let value = Self::encode(obj, chrono::Utc::now())?;
        let txn = Txn::new()
            .when(vec![Compare::mod_revision(
                key.clone(),
                CompareOp::Equal,
                rev,
            )])
            // A copy for the same reason `create` makes one.
            //
            // `ignore_lease` is what lets an expiring object be UPDATED
            // without stopping expiring: a put with no lease named would
            // otherwise take the key's lease off and make it permanent, which
            // for an event that is being aggregated is exactly the wrong
            // direction. Harmless on every other resource — a key with no
            // lease has none to keep.
            .and_then(vec![TxnOp::put(
                key.clone(),
                value.clone(),
                Some(PutOptions::new().with_ignore_lease()),
            )]);
        let resp = timed("update", self.handle().txn(txn)).await?;
        if !resp.succeeded() {
            return Err(StoreError::Conflict(format!(
                "resource version conflict on {resource}/{name} (concurrent write)",
                resource = T::RESOURCE
            )));
        }
        self.written(&name, &value, &resp).await
    }

    /// Read-modify-write with retry — for controller-owned fields (status,
    /// scheduling bindings) where the caller's edit commutes.
    pub async fn mutate<T, F>(&self, name: &str, mut f: F) -> Result<T>
    where
        T: Resource,
        F: FnMut(&mut T),
    {
        for _ in 0..8 {
            let mut obj: T = self.get(name).await?;
            f(&mut obj);
            match self.update(&obj).await {
                Ok(o) => return Ok(o),
                Err(StoreError::Conflict(_)) => continue,
                Err(e) => return Err(e),
            }
        }
        Err(StoreError::Conflict(format!(
            "resource version conflict on {resource}/{name} (retries exhausted)",
            resource = T::RESOURCE
        )))
    }

    /// Hard delete — the finalizer flow soft-deletes via update first.
    pub async fn delete<T: Resource>(&self, name: &str) -> Result<()> {
        let key = self.key(T::RESOURCE, name);
        timed("delete", self.handle().delete(key, None)).await?;
        Ok(())
    }

    /// Take an object: delete it and hand back what was there, or `None` if
    /// nothing was.
    ///
    /// One round trip, and that is the whole of it. A `get` followed by a
    /// `delete` is two, and between them a second replica does the same get
    /// and gets the same answer — so a thing that may be had exactly once is
    /// had twice. etcd's `with_prev_key` makes the read the delete's own
    /// return value, and a delete of a key that is already gone deletes
    /// nothing and returns nothing: exactly one caller can win.
    ///
    /// Written for console tickets (Fremdsicht 6) and named for what it is
    /// rather than for them, because "remove and tell me what it was" is the
    /// shape every once-only object needs.
    pub async fn take<T: Resource>(&self, name: &str) -> Result<Option<T>> {
        let key = self.key(T::RESOURCE, name);
        let options = DeleteOptions::new().with_prev_key();
        let resp = timed("take", self.handle().delete(key, Some(options))).await?;
        match resp.prev_kvs().first() {
            // The revision the object HAD, which is the one it was deleted
            // at. Nothing can be compared against it any more; it is carried
            // so that the value reads like every other object out of here.
            Some(kv) => Ok(Some(Self::decode::<T>(kv.value(), kv.mod_revision())?)),
            None => Ok(None),
        }
    }

    /// Watch a resource prefix. Yields decoded objects; Delete events carry
    /// only the name (the value is gone).
    pub async fn watch<T: Resource>(
        &self,
    ) -> Result<tokio::sync::mpsc::Receiver<(WatchEvent, String, Option<T>)>> {
        let dir = self.dir(T::RESOURCE);
        // Establishing the watch is a request like any other and is bounded;
        // the stream it hands back is not, and must not be — see `timed`.
        let opts = WatchOptions::new().with_prefix();
        let mut stream = timed("watch", self.handle().watch(dir.clone(), Some(opts))).await?;
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        tokio::spawn(async move {
            while let Ok(Some(resp)) = stream.message().await {
                for ev in resp.events() {
                    let Some(item) = Self::observed::<T>(ev) else {
                        continue;
                    };
                    if tx.send(item).await.is_err() {
                        return;
                    }
                }
            }
        });
        Ok(rx)
    }

    /// One etcd watch event in this store's own words, or `None` for one
    /// there is nothing to say about.
    ///
    /// An event without a key-value is one etcd told us nothing with. A
    /// Delete carries only the name, because the value is gone. A Put that
    /// will not decode is dropped with an error, for the reason `list` logs
    /// one: nothing heals a key that will not decode, and a watch that
    /// stopped at one would take the reconciler down with it.
    fn observed<T: Resource>(ev: &Event) -> Option<(WatchEvent, String, Option<T>)> {
        let kv = ev.kv()?;
        let name = String::from_utf8_lossy(kv.key())
            .rsplit('/')
            .next()
            .unwrap_or_default()
            .to_string();
        if ev.event_type() == EventType::Delete {
            return Some((WatchEvent::Delete, name, None));
        }
        match Self::decode::<T>(kv.value(), kv.mod_revision()) {
            Ok(obj) => Some((WatchEvent::Put, name, Some(obj))),
            Err(e) => {
                error!(name, error = format!("{e:#}"), "undecodable watch event");
                None
            }
        }
    }
}

/// Why a reconcile pass runs: a periodic tick, or something changed.
///
/// Level-triggered reconcilers do not act on events — they re-derive
/// everything from the store every pass — so the watch is only ever a reason
/// to run one sooner than the tick would. That makes losing it survivable
/// rather than fatal, and this is where that is arranged: the initial watch is
/// retried until it takes, a closed stream is re-established on the next wake,
/// and the tick carries the reconciler in the meantime.
///
/// Both tiers ran this loop, identically, thirty-odd lines each. What is
/// generic about it is `T` — the object type the watch decodes — which is the
/// same parameter `EtcdStore::watch` already takes, so nothing here is a
/// contortion to make two things one.
pub struct PassTrigger<T: Resource> {
    watch: Option<tokio::sync::mpsc::Receiver<(WatchEvent, String, Option<T>)>>,
    tick: tokio::time::Interval,
}

impl<T: Resource> PassTrigger<T> {
    /// Retries the initial watch until it takes: a controller that starts
    /// while etcd is still coming up should end up watching, not end up
    /// ticking forever.
    pub async fn new(store: &EtcdStore, period: Duration) -> Self {
        let watch = loop {
            match store.watch::<T>().await {
                Ok(w) => break w,
                Err(e) => {
                    warn!(
                        resource = T::RESOURCE,
                        error = format!("{e:#}"),
                        "watch failed, retrying"
                    );
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
        };
        let mut tick = tokio::time::interval(period);
        // Delay, not Burst: a pass that overran its period must not be
        // followed by a flurry of catch-up passes over the same objects.
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        Self {
            watch: Some(watch),
            tick,
        }
    }

    /// Wait for the next reason to run a pass. Returns when the tick fires or
    /// the store says something changed; a watch that closed is re-opened
    /// here, and until it is, the tick is what keeps the reconciler running.
    /// This never waits twice: every path here is a reason to run a pass, and
    /// a reconnect that failed is one too. Looping until the watch came back
    /// would swallow the tick that woke us and leave the reconciler making no
    /// passes at all for as long as the store stays unreachable — the opposite
    /// of what the tick is for, and exactly when a level-triggered pass is
    /// worth the most. A failed reconnect costs nothing extra either: the next
    /// call finds `watch: None` and waits for a tick before trying again.
    pub async fn wait(&mut self, store: &EtcdStore) {
        let closed = match &mut self.watch {
            Some(watch) => {
                tokio::select! {
                    _ = self.tick.tick() => return,
                    ev = watch.recv() => ev.is_none(),
                }
            }
            // No watch at the moment: the tick alone drives the passes.
            None => {
                self.tick.tick().await;
                true
            }
        };
        if !closed {
            return; // a real change
        }
        if self.watch.is_some() {
            warn!(
                resource = T::RESOURCE,
                "watch closed, falling back to ticks"
            );
            self.watch = None;
        }
        match store.watch::<T>().await {
            Ok(w) => {
                info!(resource = T::RESOURCE, "watch re-established");
                self.watch = Some(w);
            }
            Err(e) => {
                warn!(
                    resource = T::RESOURCE,
                    error = format!("{e:#}"),
                    "watch reconnect failed"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The name is the last segment of the key. A name that is not a segment
    /// produces an object at a path the API cannot address back — reachable
    /// by no GET, no DELETE, and no reconcile decision that needs its name.
    /// What the lab got past the old check, and what each one would have
    /// become downstream. A name is an etcd key, a file name and part of an
    /// interface name — three places with three different ideas of what a
    /// byte is.
    /// The difference between "pick another name" and "wait a moment". A
    /// create that loses to an object on its way out used to say the name was
    /// taken, which is not true — the object is gone and its finalizer is
    /// not done yet.
    #[test]
    fn a_name_held_by_a_dying_object_is_told_apart_from_a_name_that_is_taken() {
        let alive = br#"{"metadata":{"name":"a"}}"#;
        let dying = br#"{"metadata":{"name":"a","deletionTimestamp":"2026-08-29T13:00:00Z"}}"#;
        assert!(!EtcdStore::is_deleting(alive));
        assert!(EtcdStore::is_deleting(dying));

        // An empty stamp is not a stamp, and neither is a null.
        assert!(!EtcdStore::is_deleting(
            br#"{"metadata":{"deletionTimestamp":""}}"#
        ));
        assert!(!EtcdStore::is_deleting(
            br#"{"metadata":{"deletionTimestamp":null}}"#
        ));

        // Unreadable bytes are a plain collision, which is the answer that
        // was given before this existed — a decode failure here must not
        // turn "the name is taken" into "the store is broken".
        assert!(!EtcdStore::is_deleting(b"not json at all"));
        assert!(!EtcdStore::is_deleting(b""));
    }

    /// The default shape, and every way the lab found to get past the check
    /// before it.
    #[test]
    fn a_name_that_is_not_a_dns_label_is_refused() {
        let label = |n: &str| EtcdStore::check_name(n, NameShape::DnsLabel);
        for ok in ["web-1", "a", "vm-0", "chaos-pool-2", &"a".repeat(63)] {
            assert!(label(ok).is_ok(), "{ok:?} should be a name");
        }
        for (bad, why) in [
            (
                "has space",
                "a shell word boundary on every node that sees it",
            ),
            (
                "chaos-\u{fc}ml",
                "not one byte per character where it is counted",
            ),
            ("Web-1", "two objects differing only in case are one file"),
            ("-lead", "must start alphanumeric"),
            ("trail-", "must end alphanumeric"),
            (
                "a..b",
                "the old check caught this only when it was the whole name",
            ),
            ("under_score", "not a dns label"),
            ("debian.raw", "a dot is not part of a label"),
        ] {
            assert!(label(bad).is_err(), "{bad:?}: {why}");
        }
        let long = "a".repeat(64);
        let e = label(&long).unwrap_err().to_string();
        assert!(e.contains("64 bytes"), "{e}");
    }

    /// The wider shape, and the two resources it exists for.
    ///
    /// Both of them are named after something that was never a word an
    /// operator chose — an address, and the file a node looks an image up as
    /// — and while the label was demanded of them, NEITHER could be created
    /// at all: every floating reservation was a 422, and an image with an
    /// extension could not be catalogued.
    #[test]
    fn a_dotted_name_holds_an_address_and_a_file_name_and_still_no_traversal() {
        let dotted = |n: &str| EtcdStore::check_name(n, NameShape::Dotted);
        for ok in [
            "10.255.0.1",
            "203.0.113.11",
            "debian-13.raw",
            "nixos.qcow2",
            "web-1",
        ] {
            assert!(dotted(ok).is_ok(), "{ok:?} should be a name");
        }
        // Everything the label refuses for a reason that still holds, holds.
        for (bad, why) in [
            ("has space", "still a shell word boundary"),
            ("Debian.raw", "still one file on a case-insensitive mount"),
            ("team/web", "still one path segment"),
            ("..", "still the traversal"),
            ("a..b", "and it is refused wherever it sits, not only alone"),
            (".leading", "still starts alphanumeric"),
            ("trailing.", "still ends alphanumeric"),
            ("chaos-\u{fc}ml", "still one byte per character"),
        ] {
            assert!(dotted(bad).is_err(), "{bad:?}: {why}");
        }

        // And the two resources really carry it, which is what makes the
        // paragraph above true rather than merely available.
        assert_eq!(
            <crate::resources::FloatingIp as Resource>::NAME_SHAPE,
            NameShape::Dotted
        );
        assert_eq!(
            <crate::resources::Image as Resource>::NAME_SHAPE,
            NameShape::Dotted
        );
        // Everything an operator names keeps the label: a vm name becomes
        // part of an interface name, and that is where the rule is earned.
        assert_eq!(
            <crate::resources::Vm as Resource>::NAME_SHAPE,
            NameShape::DnsLabel
        );
        assert_eq!(
            <crate::resources::Node as Resource>::NAME_SHAPE,
            NameShape::DnsLabel
        );
    }

    #[test]
    fn a_name_that_is_not_one_path_segment_is_refused() {
        assert!(EtcdStore::check_name("web-1", NameShape::DnsLabel).is_ok());
        for bad in ["team/web", "", ".", ".."] {
            assert!(
                EtcdStore::check_name(bad, NameShape::DnsLabel).is_err(),
                "{bad:?}"
            );
            assert!(
                EtcdStore::check_name(bad, NameShape::Dotted).is_err(),
                "{bad:?}"
            );
        }
    }

    /// A request that never answers becomes an error the caller can act on,
    /// naming the operation. An etcd that has lost quorum does exactly this:
    /// it accepts the request and says nothing. Since every caller holds its
    /// own client handle the cost stops at that caller — but a caller that
    /// waits for ever is a reconcile pass that makes no more passes, so the
    /// bound is what makes it an error instead of a task that is gone.
    #[tokio::test(start_paused = true)]
    async fn a_request_that_never_answers_becomes_a_timeout() {
        let err = timed::<(), StoreError>("list", std::future::pending())
            .await
            .expect_err("pending never resolves");
        assert!(
            matches!(err, StoreError::Timeout("list", REQUEST_TIMEOUT)),
            "{err:?}"
        );
        // and the message names the operation, because "etcd timed out" tells
        // an operator nothing about which caller is stuck
        assert!(err.to_string().contains("list"), "{err}");
    }

    /// The bound is on not answering, not on answering slowly-but-in-time:
    /// a request just inside the window is a normal result.
    #[tokio::test(start_paused = true)]
    async fn a_request_inside_the_window_is_not_a_timeout() {
        let just_in_time = async {
            tokio::time::sleep(REQUEST_TIMEOUT - Duration::from_millis(1)).await;
            Ok::<_, StoreError>(7)
        };
        assert_eq!(timed("get", just_in_time).await.unwrap(), 7);
    }

    /// A real etcd error is passed through as itself, not repackaged as a
    /// timeout — "not found" and "nobody answered" are different problems and
    /// the caller treats them differently (StoreError::NotFound is a 404, a
    /// Timeout is a 503).
    #[tokio::test(start_paused = true)]
    async fn an_error_inside_the_window_stays_the_error_it_was() {
        let failed = async { Err::<(), _>(StoreError::NotFound("vms/x".into())) };
        let err = timed("get", failed).await.unwrap_err();
        assert!(matches!(err, StoreError::NotFound(_)), "{err:?}");
    }

    /// The whole of what lets `handle` replace the mutex: an etcd client is a
    /// handle and clones as one. If a future version of the crate takes that
    /// away, every store operation in the process silently goes back to
    /// standing in one queue behind whichever request is slowest — so the
    /// assumption is asserted here rather than left in a comment.
    #[test]
    fn an_etcd_client_is_a_handle_and_clones_as_one() {
        fn shares_one_connection<T: Clone + Send + Sync>() {}
        shares_one_connection::<Client>();
    }

    /// What `create` and `update` are allowed to return without reading the
    /// key back: the bytes they wrote, decoded, stamped with the revision the
    /// write produced. That is only the same object as a `get` if the encode
    /// is faithful — so this is the round trip, over a real resource with
    /// every kind of field the envelope has (skipped-when-empty, defaulted,
    /// optional timestamps, a map).
    #[test]
    fn what_was_written_decodes_back_to_what_was_written() {
        use crate::resources::{FloatingIp, FloatingIpSpec};

        let mut obj = FloatingIp::declare(
            "10.255.0.7",
            FloatingIpSpec {
                internal_address: String::new(),
                router: String::new(),
                tenant: "acme".into(),
                pool: "lab".into(),
                address: "10.255.0.7".into(),
                vm: Some("web".into()),
            },
        );
        obj.metadata.labels.insert("team".into(), "net".into());
        // A stale version on the way in is the normal case for `update`, and
        // it must not be what comes back out.
        obj.metadata.resource_version = "41".into();

        let bytes = EtcdStore::encode(&obj, chrono::Utc::now()).expect("encodes");
        let back: FloatingIp = EtcdStore::decode(&bytes, 42).expect("decodes");

        assert_eq!(back.metadata.resource_version, "42", "the write's revision");
        // Everything else is what went in, field for field: compare the
        // documents rather than the structs, which is the comparison the
        // store actually cares about.
        let mut expected = obj.clone();
        expected.metadata.resource_version = "42".into();
        assert_eq!(
            serde_json::to_value(&back).unwrap(),
            serde_json::to_value(&expected).unwrap()
        );
    }

    /// The store runs [`Resource::settle`] on the way out, and this is where
    /// that is nailed down without an etcd.
    ///
    /// Two halves. The default is a NO-OP, which is what makes struktur 4's
    /// type half behaviour-neutral: every resource in the tree writes exactly
    /// the bytes it wrote before. And a resource that does implement it is
    /// really called, with the instant the store chose — which is the
    /// contract the derivation lane is going to build on.
    #[test]
    fn the_store_settles_an_object_before_it_makes_the_bytes() {
        use crate::object::Object;
        use crate::resources::{FloatingIp, FloatingIpSpec};

        // The default: nothing in the tree implements `settle` yet, so the
        // document that goes in is the document that comes out — which is
        // the whole claim "the type half changes no behaviour".
        let plain = FloatingIp::declare(
            "10.255.0.9",
            FloatingIpSpec {
                internal_address: String::new(),
                router: String::new(),
                tenant: "acme".into(),
                pool: "lab".into(),
                address: "10.255.0.9".into(),
                vm: None,
            },
        );
        let bytes = EtcdStore::encode(&plain, chrono::Utc::now()).expect("encodes");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes).expect("json"),
            serde_json::to_value(&plain).expect("json"),
            "a resource without a settle is written verbatim"
        );

        // And one that has one: its phase is a function of its spec, which is
        // the shape every real `settle` will have.
        #[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
        struct Wanted {
            ready: bool,
        }
        #[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
        struct Derived {
            phase: String,
            at: String,
        }
        type Thing = Object<Wanted, Derived>;
        impl Resource for Thing {
            const RESOURCE: &'static str = "things";
            const KIND: &'static str = "Thing";
            fn settle(&mut self, now: chrono::DateTime<chrono::Utc>) {
                self.status.phase = if self.spec.ready { "Ready" } else { "Pending" }.to_string();
                self.status.at = now.to_rfc3339();
            }
        }

        let now = chrono::DateTime::from_timestamp(1_800_000_000, 0).expect("an instant");
        let thing = Thing::new("meister.io/v1", "Thing", "t", Wanted { ready: true });
        assert_eq!(thing.status.phase, "", "nobody has assigned anything");
        let bytes = EtcdStore::encode(&thing, now).expect("encodes");
        let back: Thing = EtcdStore::decode(&bytes, 1).expect("decodes");
        assert_eq!(back.status.phase, "Ready", "derived on the way out");
        assert_eq!(back.status.at, now.to_rfc3339(), "at the store's instant");
    }
}

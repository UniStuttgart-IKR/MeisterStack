// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Which namespace of an imported pool belongs to which volume.
//!
//! ## The defect this answers
//!
//! An `nvmeof-import` pool is a list of namespaces that already exist on a
//! target somewhere on the network. The driver used to hand them out itself,
//! with one claim file per namespace in its state directory — and the comment
//! there names `O_EXCL` as the lock, correctly. But `O_EXCL` on a filesystem
//! only one node can see locks against that one node, and the POOL is
//! cluster-wide: rollout 59 bound a second pool over the same three
//! namespaces to a node that had no claim file yet, and got two `Ready`
//! volumes on the same 100 GiB block. Had a second guest started, two VMs
//! would have written the same disk.
//!
//! The assignment belongs where the pool lives, which is this cluster's etcd
//! — where `volumes/` has always been. `StoragePool.status.claims` is the
//! table (namespace -> volume uid) and a compare-and-swap on the pool object
//! is the lock: two replicas reaching for the last free namespace both write,
//! one loses, and the loser reads the table again rather than believing what
//! it read a moment ago.
//!
//! ## The contract with the driver
//!
//! The controller writes the assignment as `namespace` into the volume's
//! driver parameters (`params_json`, a string, the namespace's NQN exactly as
//! the driver names it in `params.namespaces[].nqn`). The driver takes a
//! given `namespace` and chooses for itself ONLY when none is given and the
//! pool's config says `allow_local_claims = true`, which defaults to false.
//! So a pool written today is assigned from here, and a pool an operator
//! deliberately kept node-local still works.
//!
//! ## Why this tier reads a driver's parameters at all
//!
//! It is the one exception to "this control plane routes on `driver` and
//! reads nothing else" (`volume_spec_json`), and it is not a comfortable one.
//! The reason it has to be made here: the thing being handed out is a
//! CLUSTER-wide resource with a fixed number of pieces, so the only place
//! that can hand it out is the one place all the nodes agree on. What keeps
//! it narrow is the shape rather than a driver name — a pool whose params
//! carry a `namespaces` list is a pool of countable pieces, whichever backend
//! reads it, and a pool without one is untouched by every line below.

use std::collections::BTreeMap;

use controller_api::{EtcdStore, StoragePool, StoreError, Volume};
use tracing::{debug, info};

/// How many times a lost compare-and-swap is worth re-reading for.
///
/// Each retry means another replica assigned a namespace out of this pool in
/// the microseconds since the read, so the loop terminates for the same
/// reason the pool is finite. Eight is far past what a three-replica cluster
/// can produce and short enough that a pool object somebody is rewriting in a
/// loop does not hold a pass open.
const RETRIES: usize = 8;

/// One namespace as it stands in a pool's params. The driver's own shape,
/// read here and nowhere else in this tier.
#[derive(Clone, Debug, serde::Deserialize)]
struct Namespace {
    nqn: String,
    #[serde(default)]
    size_gib: u64,
}

/// The part of an import pool's params this tier understands: the list, and
/// whether the operator kept the old node-local assignment.
///
/// `deny_unknown_fields` is deliberately NOT set — every other key in there
/// (transport, addr, port) is the driver's business and this tier must not
/// start having opinions about it.
#[derive(Clone, Debug, Default, serde::Deserialize)]
struct NamespacePool {
    #[serde(default)]
    namespaces: Vec<Namespace>,
    /// The escape hatch, and the reason the default is false: a pool that
    /// says true is one where the operator has taken responsibility for two
    /// nodes not choosing the same namespace.
    #[serde(default)]
    allow_local_claims: bool,
}

/// What a pool says about namespaces, or nothing at all.
///
/// A pool whose params are absent, unreadable or namespace-less is not a
/// namespace pool, and none of this applies to it. Unreadable is deliberately
/// the same answer as absent: this tier does not validate a driver's options
/// — the node does, and it says so far better than a controller could.
/// A pool that says `allow_local_claims` answers `None` here too, and that is
/// the escape hatch doing its job on this side: an operator who wrote it has
/// said the nodes may choose, so nothing is assigned and the driver picks as
/// it always did. Written on both sides or it is written on neither.
fn pool_of(pool: &StoragePool) -> Option<NamespacePool> {
    let params = pool.spec.params.as_ref()?;
    let parsed: NamespacePool = serde_json::from_value(params.clone()).ok()?;
    (!parsed.namespaces.is_empty() && !parsed.allow_local_claims).then_some(parsed)
}

/// Every namespace this pool lists, whoever is allowed to hand them out.
///
/// Deliberately NOT `pool_of`: that one answers "is this a pool I assign out
/// of", and a pool with `allow_local_claims` answers no. The question here is
/// a different one — "which blocks does this pool CLAIM to be about" — and a
/// pool that lets its nodes choose is about exactly the same blocks.
fn listed(pool: &StoragePool) -> Vec<String> {
    let Some(params) = pool.spec.params.as_ref() else {
        return Vec::new();
    };
    serde_json::from_value::<NamespacePool>(params.clone())
        .map(|p| p.namespaces.into_iter().map(|n| n.nqn).collect())
        .unwrap_or_default()
}

/// The pool that already lists one of these namespaces, and which one.
///
/// # The defect this answers
///
/// `status.claims` made the assignment atomic across the nodes of ONE pool,
/// and the E2E of round 4 walked straight past it: a second pool object over
/// the same three namespaces, bound to a node that held none of them, handed
/// out `…:meisterstack-test1` a second time. Two `Ready` volumes on one
/// 100 GiB block, on two nodes — the rollout-59 finding again, by a different
/// road. The table is per pool OBJECT, so two objects have two tables, and
/// each counts from zero.
///
/// The node half cannot catch it either and never could: the driver's claim
/// files describe THIS node, and the second guest was on another one.
///
/// So the refusal belongs where the second name is invented, which is the
/// create. The comparison is on the NQN alone and not on `addr:port` beside
/// it, and that is the point rather than a shortcut: an NVMe Qualified Name
/// is unique by construction, so two pools listing one are two names for one
/// block however each of them spells the target — including the case where
/// one says an address and the other a hostname, which is the case an
/// operator is most likely to write by hand.
pub(crate) fn already_listed(
    pool: &StoragePool,
    existing: &[StoragePool],
) -> Option<(String, String)> {
    let mine = listed(pool);
    if mine.is_empty() {
        return None;
    }
    for other in existing {
        if other.metadata.name == pool.metadata.name {
            continue;
        }
        for nqn in listed(other) {
            if mine.contains(&nqn) {
                return Some((other.metadata.name.clone(), nqn));
            }
        }
    }
    None
}

/// What the table says about one volume, as a decision and nothing else.
///
/// Pure, and separate from the loop for the reason every rule in this tree
/// is: a rule that can only be exercised through an etcd is a rule that gets
/// exercised by the lab.
#[derive(Debug, PartialEq, Eq)]
enum Choice {
    /// It already has one. Nothing to write.
    Held(String),
    /// This one is free and big enough.
    Take(String),
    /// None is. The sentence goes on the volume.
    None(String),
}

/// Which namespace this volume should hold, out of what the pool lists and
/// what the table already says.
///
/// The same two rules the driver applied when it was choosing: the first
/// namespace nobody has claimed, and never one smaller than what was asked
/// for — an import hands out WHOLE namespaces, and carving one down to fit
/// would be a lie about the size the object promises.
fn choose(pool: &NamespacePool, claims: &BTreeMap<String, String>, volume: &Volume) -> Choice {
    let uid = &volume.metadata.uid;
    // First, because a provision whose answer was lost must find its own
    // namespace again rather than take a second one. Two provisions of one
    // volume are the ordinary case here — a requeue, and a migration opening
    // the disk at the destination.
    if let Some((nqn, _)) = claims.iter().find(|(_, held)| *held == uid) {
        return Choice::Held(nqn.clone());
    }
    let wanted = volume.spec.size_gib;
    for ns in &pool.namespaces {
        if claims.contains_key(&ns.nqn) {
            continue;
        }
        if ns.size_gib < wanted {
            continue;
        }
        return Choice::Take(ns.nqn.clone());
    }
    // The driver's own sentence, one tier up: it is the true one, and it is
    // now said before anything is dispatched rather than by the node.
    Choice::None(format!(
        "no free namespace in pool {} holds {wanted} GiB; {} of {} are assigned",
        volume.spec.pool,
        pool.namespaces
            .iter()
            .filter(|n| claims.contains_key(&n.nqn))
            .count(),
        pool.namespaces.len()
    ))
}

/// The namespace this volume holds, without assigning one.
///
/// What `volume_spec_json` asks, on every dispatch of every volume: the spec
/// builder is a pure read and assigning is a write. `None` covers a pool that
/// hands out nothing and a volume nobody has assigned one to yet — the second
/// is what a pool with `allow_local_claims` looks like from here, and the
/// driver then chooses as it always did.
pub(crate) fn held_by(pool: &StoragePool, volume: &Volume) -> Option<String> {
    pool_of(pool)?;
    pool.status
        .claims
        .iter()
        .find(|(_, held)| *held == &volume.metadata.uid)
        .map(|(nqn, _)| nqn.clone())
}

/// Assign this volume a namespace out of its pool, or say why there is none.
///
/// `Ok(None)` is a pool that hands out nothing — the overwhelming majority,
/// and the only cost to them is the pool object this pass already reads.
/// `Err(sentence)` is "the pool is full", which the caller writes onto the
/// volume as `Failed`: no later pass can make a namespace appear.
pub(crate) async fn assign(
    store: &EtcdStore,
    volume: &Volume,
) -> anyhow::Result<Result<Option<String>, String>> {
    for attempt in 0..RETRIES {
        let mut pool: StoragePool = store.get(&volume.spec.pool).await?;
        let Some(parsed) = pool_of(&pool) else {
            return Ok(Ok(None));
        };
        match choose(&parsed, &pool.status.claims, volume) {
            Choice::Held(nqn) => {
                debug!(volume = %volume.metadata.name, %nqn, "the namespace it already holds");
                return Ok(Ok(Some(nqn)));
            }
            Choice::None(why) => return Ok(Err(why)),
            Choice::Take(nqn) => {
                pool.status
                    .claims
                    .insert(nqn.clone(), volume.metadata.uid.clone());
                match store.update(&pool).await {
                    Ok(_) => {
                        info!(volume = %volume.metadata.name, pool = %volume.spec.pool, %nqn,
                              "namespace assigned");
                        return Ok(Ok(Some(nqn)));
                    }
                    // Another replica wrote this pool between the read and
                    // the write, which on this object nearly always means it
                    // assigned a namespace too. Read it again: what must not
                    // happen is deciding against a table that has moved.
                    Err(StoreError::Conflict(_)) => {
                        debug!(volume = %volume.metadata.name, attempt,
                               "lost the namespace race; reading the pool again");
                    }
                    Err(e) => return Err(e.into()),
                }
            }
        }
    }
    Ok(Err(format!(
        "pool {} is being written by so many replicas at once that a namespace could not be \
         assigned in {RETRIES} attempts",
        volume.spec.pool
    )))
}

/// Give this volume's namespace back to its pool.
///
/// Best effort and never fatal: the volume is going away either way, and a
/// claim left behind is a namespace that stays out of circulation until
/// somebody edits the pool — bad, but not as bad as an object that will not
/// delete. Said with a warning rather than swallowed, which is what makes it
/// findable.
///
/// The DATA on the namespace is untouched, exactly as the driver's release
/// was: an import provider made none of it and destroys none of it.
pub(crate) async fn give_back(store: &EtcdStore, volume: &Volume) {
    let uid = volume.metadata.uid.clone();
    let released = store
        .mutate::<StoragePool, _>(&volume.spec.pool, |p| {
            p.status.claims.retain(|_, held| *held != uid);
        })
        .await;
    match released {
        Ok(_) => debug!(volume = %volume.metadata.name, pool = %volume.spec.pool,
                        "namespace released; its data is untouched on the target"),
        // A pool that is gone took its table with it, which is the same
        // outcome by another road.
        Err(StoreError::NotFound(_)) => {}
        Err(e) => tracing::warn!(volume = %volume.metadata.name, pool = %volume.spec.pool,
                                 error = %format!("{e:#}"),
                                 "the namespace could not be given back to its pool"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool(sizes: &[(&str, u64)]) -> NamespacePool {
        NamespacePool {
            namespaces: sizes
                .iter()
                .map(|(nqn, size_gib)| Namespace {
                    nqn: (*nqn).into(),
                    size_gib: *size_gib,
                })
                .collect(),
            allow_local_claims: false,
        }
    }

    fn volume(name: &str, uid: &str, size_gib: u64) -> Volume {
        let mut v = controller_api::resources::new_volume(
            name,
            controller_api::VolumeSpec {
                pool: "fabric".into(),
                size_gib,
                ..Default::default()
            },
        );
        v.metadata.uid = uid.into();
        v
    }

    fn claims(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(nqn, uid)| ((*nqn).to_string(), (*uid).to_string()))
            .collect()
    }

    /// A pool object as an operator writes one: a target and a list.
    fn object(name: &str, addr: &str, nqns: &[&str]) -> StoragePool {
        StoragePool::declare(
            name,
            controller_api::StoragePoolSpec {
                driver: "nvmeof-import".into(),
                params: Some(serde_json::json!({
                    "transport": "tcp",
                    "addr": addr,
                    "port": 4422,
                    "namespaces": nqns.iter().map(|n| serde_json::json!({"nqn": n, "size_gib": 100})).collect::<Vec<_>>(),
                })),
                ..Default::default()
            },
        )
    }

    /// The e2e of round 4, as one assertion: a second pool over the same
    /// namespaces is refused, and the refusal names the pool that has them.
    ///
    /// Measured in the lab before this existed — `fabric-c` on agent-1c took
    /// `…test1` while `fabric`'s `ns-a` on agent-1a held it, both `Ready`,
    /// one block.
    #[test]
    fn a_second_pool_over_the_same_namespace_is_refused_by_name() {
        let first = object(
            "fabric",
            "10.128.0.21",
            &["nqn:test1", "nqn:test2", "nqn:test3"],
        );
        let second = object(
            "fabric-c",
            "10.128.0.21",
            &["nqn:test1", "nqn:test2", "nqn:test3"],
        );
        let (other, nqn) = already_listed(&second, std::slice::from_ref(&first)).expect("refused");
        assert_eq!(other, "fabric");
        assert_eq!(nqn, "nqn:test1");
        // ...and the pool that is already there does not collide with itself.
        assert_eq!(already_listed(&first, std::slice::from_ref(&first)), None);
    }

    /// The NQN is the identity, not the address beside it: the same block
    /// reached by name on one pool and by address on the other is still one
    /// block, and that is the shape an operator writes by hand.
    #[test]
    fn the_same_nqn_behind_two_spellings_of_one_target_is_still_one_block() {
        let by_addr = object("fabric", "10.128.0.21", &["nqn:test1"]);
        let by_name = object("fabric-dns", "target.lab", &["nqn:test1"]);
        assert!(already_listed(&by_name, std::slice::from_ref(&by_addr)).is_some());
    }

    /// Pools that share a target but no namespace are two pools, and this is
    /// the ordinary way to split one target between two clusters or two
    /// classes of workload. Nothing here may stand in its way.
    #[test]
    fn two_pools_that_split_one_target_between_them_are_both_allowed() {
        let a = object("fabric-a", "10.128.0.21", &["nqn:test1", "nqn:test2"]);
        let b = object("fabric-b", "10.128.0.21", &["nqn:test3"]);
        assert_eq!(already_listed(&b, std::slice::from_ref(&a)), None);
    }

    /// A pool that lists nothing — every lvm-thin, filesystem and nfs pool
    /// there is — is not about blocks anybody else could name, so it collides
    /// with nothing and pays nothing.
    #[test]
    fn a_pool_without_a_namespace_list_collides_with_nothing() {
        let local = StoragePool::declare(
            "local",
            controller_api::StoragePoolSpec {
                driver: "lvm-thin".into(),
                params: Some(serde_json::json!({"pool": "vg0/thin"})),
                ..Default::default()
            },
        );
        let fabric = object("fabric", "10.128.0.21", &["nqn:test1"]);
        assert_eq!(already_listed(&local, std::slice::from_ref(&fabric)), None);
        assert_eq!(already_listed(&fabric, std::slice::from_ref(&local)), None);
    }

    /// `allow_local_claims` is about WHO hands a namespace out, not about
    /// which blocks a pool is about. A pool that says it still must not be
    /// the second name for somebody else's disk.
    #[test]
    fn allow_local_claims_does_not_buy_a_second_name_for_one_block() {
        let first = object("fabric", "10.128.0.21", &["nqn:test1"]);
        let mut second = object("fabric-c", "10.128.0.21", &["nqn:test1"]);
        let params = second.spec.params.as_mut().expect("params");
        params["allow_local_claims"] = serde_json::json!(true);
        assert!(already_listed(&second, std::slice::from_ref(&first)).is_some());
    }

    /// D-P1, as the lab produced it: two volumes of one pool, decided one
    /// after the other, and the second must not get the first's namespace.
    ///
    /// This is the whole defect. The old assignment was a file in a directory
    /// only one NODE could see, so the second volume — on another node —
    /// looked at an empty directory and took `test1` again.
    #[test]
    fn two_volumes_of_one_pool_get_two_namespaces() {
        let pool = pool(&[("nqn:test1", 100), ("nqn:test2", 100), ("nqn:test3", 100)]);
        let mut table = BTreeMap::new();

        let first = volume("fabric-disk", "uid-a", 100);
        let Choice::Take(one) = choose(&pool, &table, &first) else {
            panic!("the first free namespace");
        };
        assert_eq!(one, "nqn:test1");
        table.insert(one.clone(), first.metadata.uid.clone());

        let second = volume("kollision", "uid-b", 100);
        let Choice::Take(two) = choose(&pool, &table, &second) else {
            panic!("a namespace of its own");
        };
        assert_eq!(two, "nqn:test2", "and not the block the first one is on");
    }

    /// The race the compare-and-swap is for: two replicas that read the table
    /// at the same moment both pick the same namespace, so the writer that
    /// loses must decide again rather than carry its answer.
    ///
    /// The CAS itself is the store's and is tested there; what is proved here
    /// is that the loser's second decision is a different namespace, which is
    /// the only reason re-reading is worth anything.
    #[test]
    fn the_loser_of_a_race_decides_again_and_gets_the_next_one() {
        let pool = pool(&[("nqn:test1", 100), ("nqn:test2", 100)]);
        let stale = BTreeMap::new();

        let a = volume("a", "uid-a", 100);
        let b = volume("b", "uid-b", 100);
        // Both replicas read an empty table, so both reach for the same one.
        assert_eq!(choose(&pool, &stale, &a), Choice::Take("nqn:test1".into()));
        assert_eq!(choose(&pool, &stale, &b), Choice::Take("nqn:test1".into()));

        // One of them wrote. The other's compare-and-swap lost, and this is
        // what it decides on the table it reads afterwards.
        let written = claims(&[("nqn:test1", "uid-a")]);
        assert_eq!(
            choose(&pool, &written, &b),
            Choice::Take("nqn:test2".into())
        );
    }

    /// A volume that already holds one finds its own again, which is what
    /// makes a requeue and a migration safe: both dispatch a second provision
    /// for a volume that has a namespace.
    #[test]
    fn a_volume_that_holds_a_namespace_never_takes_a_second() {
        let pool = pool(&[("nqn:test1", 100), ("nqn:test2", 100)]);
        let table = claims(&[("nqn:test1", "uid-a")]);
        assert_eq!(
            choose(&pool, &table, &volume("a", "uid-a", 100)),
            Choice::Held("nqn:test1".into())
        );
    }

    /// Whole namespaces or none: a 100 GiB namespace does not serve a 200 GiB
    /// volume, and the pool being full is a sentence and not a wait.
    #[test]
    fn a_namespace_too_small_is_not_a_namespace_and_a_full_pool_says_so() {
        let pool = pool(&[("nqn:small", 50), ("nqn:big", 200)]);
        assert_eq!(
            choose(&pool, &BTreeMap::new(), &volume("a", "uid-a", 100)),
            Choice::Take("nqn:big".into()),
            "the first one that HOLDS what was asked for"
        );

        let full = claims(&[("nqn:big", "uid-a")]);
        let Choice::None(why) = choose(&pool, &full, &volume("b", "uid-b", 100)) else {
            panic!("nothing left that fits");
        };
        assert!(why.contains("1 of 2 are assigned"), "{why}");
        assert!(why.contains("100 GiB"), "{why}");
    }

    /// A pool that hands out nothing countable is untouched by any of this,
    /// and that is most pools: an lvm-thin pool's params say `vg`, and this
    /// tier must not start reading them.
    #[test]
    fn a_pool_without_namespaces_is_not_a_namespace_pool() {
        let mut p = StoragePool::declare(
            "vg0",
            controller_api::StoragePoolSpec {
                driver: "lvm-thin".into(),
                params: Some(serde_json::json!({"pool": "vg0/thin"})),
                ..Default::default()
            },
        );
        assert_eq!(held_by(&p, &volume("a", "uid-a", 10)), None);

        // Nor one whose params this tier cannot read at all: unreadable is
        // the same answer as absent, because validating a driver's options is
        // the node's job.
        p.spec.params = Some(serde_json::json!("a string"));
        assert_eq!(held_by(&p, &volume("a", "uid-a", 10)), None);

        // And the import pool IS one, with everything else in its params left
        // alone.
        p.spec.params = Some(serde_json::json!({
            "transport": "tcp", "addr": "10.128.0.21", "port": 4422,
            "namespaces": [{"nqn": "nqn:test1", "size_gib": 100}],
        }));
        p.status.claims = claims(&[("nqn:test1", "uid-a")]);
        assert_eq!(
            held_by(&p, &volume("a", "uid-a", 100)),
            Some("nqn:test1".into())
        );
        assert_eq!(
            held_by(&p, &volume("b", "uid-b", 100)),
            None,
            "somebody else's namespace is not this volume's"
        );
    }

    /// The whole of it against a real etcd, from two replicas at once — the
    /// one thing no in-process test can say, because what is being proved is
    /// that "once" holds across two processes that share nothing but a store.
    ///
    /// `#[ignore]` for the reason the ticket test next door is: it needs
    /// something to talk to. Start one and name it:
    ///
    /// ```text
    /// etcd --data-dir /tmp/ms-runde4-controller-etcd \
    ///      --listen-client-urls http://127.0.0.1:3790 \
    ///      --advertise-client-urls http://127.0.0.1:3790 \
    ///      --listen-peer-urls http://127.0.0.1:3791 \
    ///      --initial-advertise-peer-urls http://127.0.0.1:3791 \
    ///      --initial-cluster default=http://127.0.0.1:3791
    ///
    /// MEISTER_TEST_ETCD=http://127.0.0.1:3790 \
    ///   cargo test -p meister-cluster-controller -- --ignored
    /// ```
    #[tokio::test]
    #[ignore = "needs an etcd; see the note above"]
    async fn two_replicas_assigning_at_once_hand_out_two_namespaces() {
        let endpoint = std::env::var("MEISTER_TEST_ETCD")
            .unwrap_or_else(|_| "http://127.0.0.1:23700".to_string());
        // A prefix per run, so a failed one leaves nothing the next trips on.
        let prefix = format!("/namespaces-test/{}", uuid::Uuid::new_v4());
        // Two replicas: two connections, one store underneath. That is what a
        // three-replica cluster is, with the third left out because two is
        // what it takes to race.
        let one = EtcdStore::connect(std::slice::from_ref(&endpoint), &prefix)
            .await
            .expect("an etcd to talk to — see the note above");
        let two = EtcdStore::connect(&[endpoint], &prefix)
            .await
            .expect("an etcd to talk to");

        let mut fabric = StoragePool::declare(
            "fabric",
            controller_api::StoragePoolSpec {
                driver: "nvmeof-import".into(),
                params: Some(serde_json::json!({
                    "transport": "tcp", "addr": "10.128.0.21", "port": 4422,
                    "namespaces": [
                        {"nqn": "nqn:test1", "size_gib": 100},
                        {"nqn": "nqn:test2", "size_gib": 100},
                    ],
                })),
                ..Default::default()
            },
        );
        fabric = one.create(&fabric).await.expect("the pool");

        let a = volume("fabric-disk", "uid-a", 100);
        let b = volume("kollision", "uid-b", 100);
        // At the same time, from two replicas, which is exactly how the lab
        // produced two Ready volumes on one block.
        let (first, second) = tokio::join!(assign(&one, &a), assign(&two, &b));
        let first = first.expect("no store error").expect("a namespace");
        let second = second.expect("no store error").expect("a namespace");
        assert_ne!(
            first, second,
            "two volumes of one pool never share a namespace"
        );

        // And the table says so, from either replica.
        let read: StoragePool = two.get("fabric").await.expect("the pool");
        assert_eq!(read.status.claims.len(), 2);
        assert_eq!(
            read.status.claims.get(&first.clone().unwrap()).unwrap(),
            "uid-a"
        );
        assert_eq!(
            read.status.claims.get(&second.clone().unwrap()).unwrap(),
            "uid-b"
        );

        // A third volume finds the pool full, and the sentence says so
        // before anything is dispatched.
        let c = volume("third", "uid-c", 100);
        let full = assign(&one, &c).await.expect("no store error");
        assert!(
            full.as_ref()
                .is_err_and(|why| why.contains("2 of 2 are assigned")),
            "{full:?}"
        );

        // Giving one back puts it into circulation again.
        give_back(&one, &a).await;
        let again = assign(&two, &c)
            .await
            .expect("no store error")
            .expect("the namespace uid-a let go of");
        assert_eq!(again, first);

        let _ = one.delete::<StoragePool>("fabric").await;
        let _ = fabric;
    }
}

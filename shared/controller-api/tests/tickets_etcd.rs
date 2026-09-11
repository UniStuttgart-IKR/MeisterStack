// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Console tickets against a real etcd, from two replicas at once.
//!
//! `#[ignore]` because it needs something to talk to, and the workspace's
//! ordinary run has nothing: every other test in this repo is in-process.
//! Start one and name it, then ask for them by name:
//!
//! ```text
//! etcd --data-dir /tmp/ms-struktur2-etcd \
//!      --listen-client-urls http://127.0.0.1:23700 \
//!      --advertise-client-urls http://127.0.0.1:23700 \
//!      --listen-peer-urls http://127.0.0.1:23701 \
//!      --initial-advertise-peer-urls http://127.0.0.1:23701 \
//!      --initial-cluster default=http://127.0.0.1:23701
//!
//! MEISTER_TEST_ETCD=http://127.0.0.1:23700 \
//!   cargo test -p meister-controller-api --test tickets_etcd -- --ignored
//! ```
//!
//! What these prove is the one thing no in-process test can: that "once"
//! holds over two replicas that share nothing but their store (Fremdsicht 6).
//! Two `Tickets` values on two `EtcdStore` connections against one etcd are
//! exactly what a cloud behind a load balancer is.

use std::sync::Arc;

use meister_controller_api::EtcdStore;
use meister_controller_api::auth::{AuthChain, AuthRequest, Authenticator, Identity, Role};
use meister_controller_api::rest::{AuthState, guard};
use meister_controller_api::tickets::{Bearer, Tickets};

/// The endpoint the etcd above is listening on.
fn endpoint() -> String {
    std::env::var("MEISTER_TEST_ETCD").unwrap_or_else(|_| "http://127.0.0.1:23700".to_string())
}

/// One replica: its own connection, the same store underneath.
///
/// A prefix per test, so two of these running side by side cannot read each
/// other's tickets and a failed run leaves nothing behind that the next one
/// trips over.
async fn replica(prefix: &str) -> Tickets {
    let store = EtcdStore::connect(&[endpoint()], prefix)
        .await
        .expect("an etcd to talk to — see the module note");
    Tickets::new(Arc::new(store))
}

fn bearer() -> Bearer {
    Bearer {
        identity: Identity::new("alice", vec!["meister:members".to_string()]),
        role: Some(Role::Member),
        tenant: Some("acme".into()),
    }
}

const CONSOLE: &str = "/apis/meister.io/v1/vms/web-1/console";

/// The whole of the fix, and the reason it needed a real store.
///
/// A browser mints at whichever replica the load balancer picked and opens
/// the `WebSocket` at whichever it picks next. While a ticket lived in one
/// process's memory that was two thirds of the consoles at a three-replica
/// cloud, refused with a sentence that reads like a forged credential.
///
/// And the other half in the same test, because they are one property: the
/// ticket that crosses is still spent exactly once. B redeems it, and A —
/// the replica that made it — is then refused.
#[tokio::test]
#[ignore = "needs a local etcd; see the module note"]
async fn a_ticket_minted_at_one_replica_is_spent_once_at_another() {
    let a = replica("/ms-struktur2-tickets-cross").await;
    let b = replica("/ms-struktur2-tickets-cross").await;

    let token = a.mint(bearer(), CONSOLE).await.expect("minting");

    let redeemed = b
        .redeem(&token, CONSOLE)
        .await
        .expect("the sister replica opens the console this ticket was made for");
    assert_eq!(redeemed.identity.name, "alice");
    assert_eq!(redeemed.role, Some(Role::Member));
    assert_eq!(redeemed.tenant.as_deref(), Some("acme"));
    assert!(
        redeemed.identity.has_group("meister:members"),
        "the caller as they were, groups and all"
    );

    // Once, over both of them. The take is a delete that returns what it
    // deleted, so the second reader finds no key rather than a value it has
    // to be trusted to throw away.
    assert!(
        a.redeem(&token, CONSOLE).await.is_none(),
        "the replica that minted it is refused after the other spent it"
    );
    assert!(b.redeem(&token, CONSOLE).await.is_none());
    assert_eq!(a.outstanding().await, 0);
}

/// The four ways a ticket is not one, and the one way it is.
///
/// Verbatim in intent from the unit test this replaces: the same five
/// assertions, now against the store they really run on. The path binding and
/// the spend-on-presentation are the two that carry security weight, and both
/// are asked across replicas here rather than within one process.
#[tokio::test]
#[ignore = "needs a local etcd; see the module note"]
async fn a_ticket_opens_one_path_once() {
    let a = replica("/ms-struktur2-tickets-once").await;
    let b = replica("/ms-struktur2-tickets-once").await;

    let token = a.mint(bearer(), CONSOLE).await.expect("minting");
    // Another VM's console is another door.
    assert!(
        b.redeem(&token, "/apis/meister.io/v1/vms/web-2/console")
            .await
            .is_none()
    );
    // ... and presenting it at all spent it, so the right path is now closed
    // too. A wrong guess must not be retryable — not at this replica and not
    // at the one next to it.
    assert!(a.redeem(&token, CONSOLE).await.is_none());
    assert!(b.redeem(&token, CONSOLE).await.is_none());

    let token = b.mint(bearer(), CONSOLE).await.expect("minting");
    assert!(a.redeem(&token, CONSOLE).await.is_some());
    // Once.
    assert!(a.redeem(&token, CONSOLE).await.is_none());
    // Never issued. A well-formed token, so it is a name the store looks up
    // rather than one it refuses — the refusal has to come from the key not
    // being there.
    assert!(a.redeem(&"0".repeat(62), CONSOLE).await.is_none());
    assert_eq!(b.outstanding().await, 0);
}

/// A link that authenticates nobody, so that whatever passes the guard passed
/// on the ticket alone.
struct Never;
impl Authenticator for Never {
    fn authenticate(&self, _: &AuthRequest) -> anyhow::Result<Option<Identity>> {
        Ok(None)
    }
}

/// The guard's half, moved here with the store it now needs.
///
/// A browser opening a `WebSocket` cannot set an `Authorization` header, so
/// the only credential it can present is in the query string — and a
/// credential in a query string is a credential in an access log. This is
/// what makes that acceptable: the guard spends it, once, for the one path it
/// was minted for, and it carries what its holder already had.
///
/// It used to run in process with an in-memory map. It cannot any more, and
/// that is the point of the change rather than a cost of it: the redeem is a
/// round trip to the store, because that is the only place "once" is true for
/// more than one replica.
#[tokio::test]
#[ignore = "needs a local etcd; see the module note"]
async fn a_console_ticket_is_a_credential_for_one_url_and_one_use() {
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request as HttpRequest, StatusCode};
    use axum::routing::get;
    use tower::ServiceExt as _;

    let tickets = Arc::new(replica("/ms-struktur2-tickets-guard").await);
    let app = || {
        guard(
            Router::new().route(
                "/apis/meister.io/v1/vms/{name}/console",
                get(|| async { "console" }),
            ),
            AuthState {
                // Nothing else gets in: whatever passes below passed on the
                // ticket alone.
                chain: Arc::new(AuthChain::new(vec![Box::new(Never)])),
                directory: None,
                provision_oidc_users: false,
                own_peer: None,
                tickets: Some(tickets.clone()),
            },
        )
    };
    let ask = async |uri: String| {
        app()
            .oneshot(HttpRequest::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap()
            .status()
    };

    // No ticket, and a chain that knows nobody.
    assert_eq!(ask(CONSOLE.to_string()).await, StatusCode::UNAUTHORIZED);

    let token = tickets.mint(bearer(), CONSOLE).await.expect("minting");
    assert_eq!(
        ask(format!("{CONSOLE}?ticket={token}")).await,
        StatusCode::OK
    );
    // Once. A replay is not a second console.
    assert_eq!(
        ask(format!("{CONSOLE}?ticket={token}")).await,
        StatusCode::UNAUTHORIZED
    );

    // And the path it names is the path it opens.
    let token = tickets.mint(bearer(), CONSOLE).await.expect("minting");
    assert_eq!(
        ask(format!(
            "/apis/meister.io/v1/vms/web-2/console?ticket={token}"
        ))
        .await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        ask(format!("{CONSOLE}?ticket={token}")).await,
        StatusCode::UNAUTHORIZED,
        "and presenting it at the wrong door spent it"
    );
}

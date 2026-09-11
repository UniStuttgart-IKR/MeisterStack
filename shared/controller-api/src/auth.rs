// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Who is calling, and what they may do.
//!
//! Kubernetes' answer, kept: authentication is a chain of authenticators that
//! each look at a request and either recognise it or pass; identity is a name
//! plus a set of groups; and the identity lives in the client certificate
//! while the authorization objects live in etcd. Nothing here reads a private
//! key, because nothing here has one to read.
//!
//! The chain's contract is the part worth stating twice. `Ok(None)` means
//! "not mine, ask the next one". `Err` means "mine, and no" — and it ends the
//! chain, because a request that has failed a real check must not get a
//! second opinion from a weaker one behind it. An empty chain is not a broken
//! chain: it is the anonymous mode this stack ran in for its first four
//! milestones, and it stays the default.

use std::path::Path;

use chrono::{DateTime, Utc};
use pki::CertInfo;
use rustls_pki_types::CertificateDer;
use serde::{Deserialize, Serialize};

use crate::object::Resource;
use crate::resources::{CertificateSigningRequest, FloatingIp, Image, Tenant, User, Vm, Volume};

/// Groups whose name starts with this are the stack's own machinery — nodes,
/// controllers — rather than people. Kubernetes' convention, and its meaning:
/// a system identity is trusted with the tier it belongs to.
pub const SYSTEM_PREFIX: &str = "system:";
/// The group a node's certificate carries; its CN is `system:node:<node_id>`.
pub const GROUP_NODES: &str = "system:nodes";
/// The same one tier up: CN `system:cluster:<cluster_name>`.
pub const GROUP_CLUSTERS: &str = "system:clusters";
/// And one tier up again: CN `system:cloud:<cloud_name>`.
///
/// The three replicas of one cloud SHARE this name, exactly as the three
/// replicas of a cluster share theirs. It is the cloud's identity and not a
/// replica's: what it is for is a replica asking its sibling for a console,
/// and "which of the three am I talking to" is not a question that has an
/// answer worth authorizing against — they are interchangeable by design.
pub const GROUP_CLOUDS: &str = "system:clouds";
/// The four groups a user certificate can carry, one each.
pub const GROUP_ADMINS: &str = "meister:admins";
pub const GROUP_OPERATORS: &str = "meister:operators";
pub const GROUP_MEMBERS: &str = "meister:members";
pub const GROUP_VIEWERS: &str = "meister:viewers";
/// Break glass. Kubernetes' own group, with Kubernetes' own meaning: a
/// certificate carrying it is above the directory and answers to no `User`
/// object at all.
///
/// It exists because the directory has a bootstrap problem — the first user
/// has to be created by somebody, and until that somebody exists there is
/// nobody the directory knows. `tools/meister-ca` mints exactly one of these,
/// and the static bearer token is the other one. Both are meant to be used
/// twice and then left alone.
pub const GROUP_MASTERS: &str = "system:masters";

/// What a `User` may do. It is a field on the object in etcd — that is where
/// the truth is — and the signer stamps the matching group into the
/// certificate it issues so that a person holding one can read what it is
/// for. Since the permission table below, that group is a LABEL: the cloud
/// takes the role out of the directory, and the cluster refuses a user
/// certificate outright.
///
/// Four, and the two new ones are the two halves the first two conflated.
/// `Operator` is somebody who drains a node and declares a pool and has no
/// business in the user directory; `Viewer` is somebody who may look and not
/// touch, which is what an on-call rotation and a dashboard both want and
/// what `Member` was being stretched to mean.
#[derive(
    schemars::JsonSchema, Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Admin,
    Operator,
    #[default]
    Member,
    Viewer,
}

impl Role {
    /// Every role, most to least. The order here is what `from_groups` reads
    /// when a certificate carries two of them; the ORDERING of the type is
    /// `rank` below, and the test nails both.
    pub const ALL: [Role; 4] = [Role::Admin, Role::Operator, Role::Member, Role::Viewer];

    /// Least to most. `Viewer < Member < Operator < Admin` is the whole
    /// policy's backbone: the table says the least role a thing needs, and
    /// `permits` asks whether the caller is at least that.
    ///
    /// Written out rather than derived from the declaration order, because
    /// deriving it would make reordering the variants a silent policy change.
    fn rank(self) -> u8 {
        match self {
            Role::Viewer => 0,
            Role::Member => 1,
            Role::Operator => 2,
            Role::Admin => 3,
        }
    }

    /// The group a certificate carries for this role.
    pub fn group(self) -> &'static str {
        match self {
            Role::Admin => GROUP_ADMINS,
            Role::Operator => GROUP_OPERATORS,
            Role::Member => GROUP_MEMBERS,
            Role::Viewer => GROUP_VIEWERS,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::Operator => "operator",
            Role::Member => "member",
            Role::Viewer => "viewer",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.as_str() == s)
    }

    /// The role a set of groups implies, if any. The highest wins: a
    /// certificate carrying two is not a puzzle worth solving in the negative
    /// direction.
    pub fn from_groups(groups: &[String]) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|r| groups.iter().any(|g| g == r.group()))
    }
}

impl Ord for Role {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.rank().cmp(&other.rank())
    }
}

impl PartialOrd for Role {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Who is calling. Exactly K8s' shape, and for the same reason: a name is
/// what an audit line needs, groups are what a policy can be written against
/// without naming people.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Identity {
    pub name: String,
    pub groups: Vec<String>,
}

impl Identity {
    pub fn new(name: impl Into<String>, groups: Vec<String>) -> Self {
        Self {
            name: name.into(),
            groups,
        }
    }

    pub fn has_group(&self, group: &str) -> bool {
        self.groups.iter().any(|g| g == group)
    }

    /// A node, a controller, or anything else the stack runs itself.
    pub fn is_system(&self) -> bool {
        self.name.starts_with(SYSTEM_PREFIX)
            || self.groups.iter().any(|g| g.starts_with(SYSTEM_PREFIX))
    }

    /// The role this identity's certificate claims.
    ///
    /// Nothing in the authorization path reads this any more, and that is the
    /// permission table's doing: the cloud takes the role out of the
    /// directory, and a tier without a directory authorizes no person at all.
    /// What the group in a certificate is now is a LABEL — so that somebody
    /// holding one can read what it was issued for — and this is how to read
    /// it. See `rest::grant_of`.
    pub fn claimed_role(&self) -> Option<Role> {
        Role::from_groups(&self.groups)
    }

    /// The certificate name a peer of `kind` ("node", "cluster") called
    /// `peer` gets from the generator.
    pub fn peer_name(kind: &str, peer: &str) -> String {
        format!("{SYSTEM_PREFIX}{kind}:{peer}")
    }

    /// A session says who it is in its Hello, and its certificate says who it
    /// is too. When the certificate is specific — `system:node:manacor` —
    /// they have to agree, or one node's key would let it report as any
    /// other. A certificate that only carries `O=system:nodes` under some
    /// other CN is a shared identity: allowed, and worth exactly what sharing
    /// a key is worth.
    ///
    /// The KIND is half of "specific", and leaving it out was a hole rather
    /// than a shortcut. This used to strip `system:<kind>:` and let anything
    /// that did not start with it through as unnamed — so `system:node:x`
    /// asked whether it may speak for a CLUSTER did not start with
    /// `system:cluster:`, fell into the shared-identity branch, and was
    /// allowed to be any cluster it liked. One CA signs both tiers
    /// (`tools/meister-ca`), and the cloud's session port trusts it, so a
    /// node's key was a key to the cloud session of every cluster. A name
    /// that names a peer at all therefore has to name THIS kind and THIS
    /// peer; a name with no `system:<kind>:<peer>` shape names no peer and
    /// keeps the shared identity it always had.
    pub fn may_speak_for(&self, kind: &str, peer: &str) -> bool {
        let Some(rest) = self.name.strip_prefix(SYSTEM_PREFIX) else {
            return true;
        };
        match rest.split_once(':') {
            Some((named_kind, named_peer)) => named_kind == kind && named_peer == peer,
            None => true,
        }
    }
}

impl std::fmt::Display for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.groups.is_empty() {
            f.write_str(&self.name)
        } else {
            write!(f, "{} [{}]", self.name, self.groups.join(","))
        }
    }
}

/// Everything an authenticator is allowed to look at.
///
/// Owned and transport-free on purpose: the certificate chain arrives from
/// rustls at the REST edge and from tonic at the session edge, and an
/// authenticator that took either of those types would be testable only
/// through a TLS handshake.
#[derive(Debug, Default)]
pub struct AuthRequest {
    /// The peer's certificate chain, leaf first, DER. Empty = no client
    /// certificate was presented (plain http, or TLS without one).
    pub peer_certs: Vec<Vec<u8>>,
    /// The `Authorization` header, verbatim.
    pub authorization: Option<String>,
}

impl AuthRequest {
    pub fn with_certs(peer_certs: Vec<Vec<u8>>) -> Self {
        Self {
            peer_certs,
            authorization: None,
        }
    }
}

pub trait Authenticator: Send + Sync {
    /// `Ok(None)` = not my business, ask the next link. `Ok(Some)` = this is
    /// who it is. `Err` = I checked, and no — which ends the chain.
    fn authenticate(&self, req: &AuthRequest) -> anyhow::Result<Option<Identity>>;

    /// Can this link authenticate anybody right now?
    ///
    /// The difference between CONFIGURED and READY, and D11 is what it is
    /// for: the lab's cloud offered `auth=mtls,oidc` in its discovery
    /// document for hours while the identity provider was unreachable and no
    /// signing key had ever been fetched. Every token would have been
    /// refused. A client that reads the document and believes it gets a
    /// promise that does not hold, and the failure lands at the far end.
    ///
    /// `true` by default, because it is true of every link whose readiness is
    /// its construction: an mTLS authenticator holds a CA it was given, and a
    /// bearer link holds a token it was given. Only a link that loads
    /// something from somewhere else has a second state, and only that link
    /// overrides this.
    fn ready(&self) -> bool {
        true
    }
}

/// What the chain concluded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Authenticated {
    /// No chain is configured. Every request is anonymous and may do
    /// anything — the behaviour of M1 through M4, and the default.
    Anonymous,
    As(Identity),
}

/// A request the chain refused, with the reason to put in the 401 body. Its
/// own type rather than an anyhow::Error so that "nobody recognised this" and
/// "somebody checked this and said no" cannot be confused at the call site.
#[derive(Debug)]
pub struct Rejected(pub String);

impl std::fmt::Display for Rejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Default)]
pub struct AuthChain {
    links: Vec<Box<dyn Authenticator>>,
    /// What each link is, in order, for the discovery document: "mtls",
    /// "oidc", "bearer". A name and not the link itself, because what a
    /// client needs from this is which credentials the endpoint will look at
    /// — the CA path and the token behind them are nobody else's business.
    names: Vec<&'static str>,
}

/// How many links, and nothing about what they are: an authenticator's
/// configuration is a CA path or a token, and neither belongs in a Debug
/// line that could end up in a log.
impl std::fmt::Debug for AuthChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AuthChain({} links)", self.links.len())
    }
}

impl AuthChain {
    /// A chain that does not say what it is made of. `rest::build_chain` is
    /// the one place a real one is assembled and it uses `named`; this is for
    /// tests, where the links are anonymous by construction.
    pub fn new(links: Vec<Box<dyn Authenticator>>) -> Self {
        Self {
            links,
            names: Vec::new(),
        }
    }

    /// The same, with the config names of the links.
    pub fn named(links: Vec<Box<dyn Authenticator>>, names: Vec<&'static str>) -> Self {
        Self { links, names }
    }

    /// What a discovery document says under `auth`: the links, comma-joined,
    /// or `none` when nothing is configured.
    ///
    /// `none` is not "unknown": it is the anonymous mode this stack has run
    /// in since M1, and a client that reads it may say so out loud rather
    /// than waiting for a 401 that will never come.
    ///
    /// A link that is configured and cannot authenticate anybody yet is named
    /// `<name>:degraded` (D11). Named rather than dropped, and that is the
    /// decision: dropping it would make "this deployment has no identity
    /// provider" and "the identity provider is unreachable" the same
    /// sentence, and they need different people. `:degraded` says the door
    /// exists and is shut, which is what an operator has to know and what a
    /// client has to stop relying on.
    ///
    /// Asked at the moment it is answered and never cached — see
    /// `rest::discovery`. A snapshot taken when the router was built would
    /// say `degraded` for ever, because at start-up nothing has loaded yet.
    pub fn describe(&self) -> String {
        if self.names.is_empty() {
            return "none".to_string();
        }
        self.names
            .iter()
            .zip(self.links.iter())
            .map(|(name, link)| match link.ready() {
                true => (*name).to_string(),
                false => format!("{name}:degraded"),
            })
            .collect::<Vec<_>>()
            .join(",")
    }

    pub fn is_empty(&self) -> bool {
        self.links.is_empty()
    }

    pub fn len(&self) -> usize {
        self.links.len()
    }

    /// Walk the chain. First link that recognises the request wins; the first
    /// link that refuses it ends the walk.
    pub fn authenticate(&self, req: &AuthRequest) -> Result<Authenticated, Rejected> {
        if self.links.is_empty() {
            return Ok(Authenticated::Anonymous);
        }
        for link in &self.links {
            match link.authenticate(req) {
                Ok(Some(identity)) => return Ok(Authenticated::As(identity)),
                Ok(None) => continue,
                // A hard no. Nothing behind it gets a say, because a weaker
                // authenticator saying yes after a stronger one said no is
                // exactly the bypass this rule exists to prevent.
                Err(e) => return Err(Rejected(format!("{e:#}"))),
            }
        }
        Err(Rejected("no credentials were presented".into()))
    }
}

/// Identity out of a client certificate: CN is the name, every O is a group.
///
/// rustls has already checked the chain by the time a REST handler runs, so
/// checking it again here is belt and braces — but it is the belt and braces
/// that make this testable from two PEM files with no socket involved, and
/// the certificate has to be parsed for its subject anyway. One parse, both
/// answers.
pub struct MtlsAuthenticator {
    cas: Vec<CertificateDer<'static>>,
}

impl MtlsAuthenticator {
    pub fn new(cas: Vec<CertificateDer<'static>>) -> Self {
        Self { cas }
    }

    pub fn from_pem_file(path: &Path) -> anyhow::Result<Self> {
        Ok(Self::new(pki::load_certs(path)?))
    }

    /// The whole of `authenticate`, with the clock passed in — which is what
    /// lets a test say "and eleven days later".
    pub fn authenticate_at(
        &self,
        req: &AuthRequest,
        now: DateTime<Utc>,
    ) -> anyhow::Result<Option<Identity>> {
        let Some(leaf) = req.peer_certs.first() else {
            // No certificate at all is not a rejection: it may be a bearer
            // token, and it may be a request that will be told 401 by the
            // chain as a whole. Refusing here would end the chain.
            return Ok(None);
        };
        let info = CertInfo::verified_by(leaf, &self.cas, now)?;
        Ok(Some(identity_of(&info)))
    }
}

/// The mapping, in one place because two tiers and the generator all have to
/// mean the same thing by it.
pub fn identity_of(info: &CertInfo) -> Identity {
    Identity {
        name: info.common_name.clone(),
        groups: info.organizations.clone(),
    }
}

impl Authenticator for MtlsAuthenticator {
    fn authenticate(&self, req: &AuthRequest) -> anyhow::Result<Option<Identity>> {
        self.authenticate_at(req, Utc::now())
    }
}

/// A single static token that stands for one identity.
///
/// This is a development path and is labelled one wherever it appears: there
/// is no expiry, no rotation and no per-user token, so a token that leaks is
/// a permanent credential. It exists because the CSR flow has a chicken and
/// egg problem — the first request a new user makes is the one asking for the
/// certificate they do not have yet — and because a lab wants a way in that
/// does not involve a CA.
pub struct BearerAuthenticator {
    token: String,
    identity: Identity,
}

impl BearerAuthenticator {
    pub fn new(token: impl Into<String>, identity: Identity) -> Self {
        Self {
            token: token.into(),
            identity,
        }
    }
}

impl Authenticator for BearerAuthenticator {
    fn authenticate(&self, req: &AuthRequest) -> anyhow::Result<Option<Identity>> {
        let Some(header) = &req.authorization else {
            return Ok(None);
        };
        let Some(presented) = header.strip_prefix("Bearer ") else {
            // Some other scheme. Not ours, and not a refusal.
            return Ok(None);
        };
        // Length-independent enough for a lab, and constant in the part that
        // matters: it does not return early on the first differing byte.
        let presented = presented.trim();
        let same = presented.len() == self.token.len()
            && presented
                .bytes()
                .zip(self.token.bytes())
                .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                == 0;
        if !same {
            anyhow::bail!("the bearer token is not the configured one");
        }
        Ok(Some(self.identity.clone()))
    }
}

// --- authorization ---------------------------------------------------------

/// What a request wants of an object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verb {
    Read,
    Write,
    /// Saying yes to a certificate request. Its own verb because it is the
    /// one write in this API that hands out a credential, and the one an
    /// admin must not be able to do by accident through a generic PUT.
    Approve,
}

/// A request, classified: which resource, which verb.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attempt<'a> {
    pub resource: &'a str,
    pub subresource: Option<&'a str>,
    pub verb: Verb,
}

/// Classify a request from its method and path.
///
/// `None` means the path is not an API object route at all — /healthz and
/// /readyz — and those are never gated: a probe that needs a certificate is a
/// probe that cannot tell "down" from "not invited".
///
/// Two API paths are in that set too, and for one reason: what they answer is
/// not an object. The discovery document falls out of the prefix (there is no
/// segment under the group-version at all), and `/schemas` is named here —
/// the comment over `SCHEMAS_PATH` has always said it should be let past
/// "exactly as it lets discovery past, the shape of an object is not a
/// secret", and the code did not do it. A build-time generator needed a
/// credential for a document with nothing in it but field names.
pub fn classify<'a>(method: &str, path: &'a str) -> Option<Attempt<'a>> {
    let rest = path.strip_prefix("/apis/meister.io/v1/")?;
    let rest = rest.split('?').next().unwrap_or(rest);
    // The document, and only the document: anything UNDER it would be a
    // route this API does not serve, and `statuses` answers those with a 404
    // rather than this function with a shrug.
    if rest.trim_end_matches('/') == "schemas" {
        return None;
    }
    let mut parts = rest.split('/').filter(|s| !s.is_empty());
    let resource = parts.next()?;
    let _name = parts.next();
    let subresource = parts.next();
    // A CORS preflight carries no credentials by definition, so classifying
    // it as a write would answer 401 to the question the browser asks BEFORE
    // it is willing to send any. Not a permission: the router has no OPTIONS
    // handler, so an unanswered preflight is a 405 exactly as it was.
    if method == "OPTIONS" {
        return None;
    }
    let verb = match (method, subresource) {
        ("GET" | "HEAD", _) => Verb::Read,
        (_, Some("approval")) => Verb::Approve,
        _ => Verb::Write,
    };
    Some(Attempt {
        resource,
        subresource,
        verb,
    })
}

/// The resources a member may write inside its own tenant. Everything else —
/// tenants, users, clusters, nodes — stays an admin's, read-only for a member
/// exactly as it was in M4.5.
///
/// `floatingips` is here and `floatingpools` and `routedsubnets` are not, and
/// that split IS the assignment rule: what exists (the pools, the subnets) is
/// an administrator's to decide, and taking one address out of a pool is
/// self-service — but only as far as that pool's quota for this tenant goes,
/// which defaults to zero on a public pool. So a member reaching this door
/// still meets the quota behind it; the door being open is what makes a lab
/// usable without a ticket per address.
///
/// `volumes` is here and `storagepools` is not, which is the same split with
/// storage nouns and for the same reason: which disks EXIST is an
/// administrator's decision, taking room out of one is self-service inside
/// that pool's per-tenant ceiling. A volume is the first tenant-scoped object
/// whose deletion can destroy something irreplaceable, which is a reason to
/// be careful in the HANDLER (see the release finalizer) and not a reason to
/// shut this door — a member who cannot make a disk cannot make a VM.
const TENANT_SCOPED: [&str; 8] = [
    Vm::RESOURCE,
    Image::RESOURCE,
    FloatingIp::RESOURCE,
    Volume::RESOURCE,
    // A snapshot is a copy of a tenant's data and is therefore the tenant's,
    // by exactly the argument the volume it came from is.
    crate::resources::VolumeSnapshot::RESOURCE,
    // A secret is the tenant's own bytes and nothing else is: there is no
    // administrator's half to it the way a pool is the half of a volume.
    // Which makes the READ half of this door the interesting one — and it is
    // shut by the object rather than by the table, because what a read of a
    // secret answers with is its key NAMES. See `Secret::redacted`.
    crate::resources::Secret::RESOURCE,
    // A migration is a record of what happened to a tenant's VM, so it is
    // filed in that tenant and read by them. It is the one resource here
    // whose WRITE door is not the tenant's — see `Class::TenantOperated`.
    crate::resources::VmMigration::RESOURCE,
    // A router is filed in a tenant for exactly that reason: it is that
    // tenant's way out and nobody else's, and a member should be able to see
    // whether theirs is up. It is the SECOND resource whose write door is not
    // the tenant's, and the same argument makes it so — a router names the
    // operator's provider network and takes a gateway slot on the operator's
    // machines, which is running the estate rather than using it. See
    // `Class::TenantOperated`.
    crate::resources::Router::RESOURCE,
];

/// Whether a resource is one whose objects belong to a tenant.
pub fn is_tenant_scoped(resource: &str) -> bool {
    TENANT_SCOPED.contains(&resource)
}

/// What KIND of thing a resource is, for the purposes of the table below.
///
/// Four classes and not fourteen resources, because the sentence an operator
/// has to be able to say out loud is "an operator drains machines and does
/// not touch the directory" — not a list. A resource that does not fit one of
/// these is a resource that needs a fifth class and a paragraph, which is the
/// point of making it an enum.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    /// Who exists and what they may do: `tenants`, `users`, and saying yes to
    /// a certificate request. An admin's, all of it.
    Directory,
    /// The estate: clusters, nodes, and the pools and subnets an operator was
    /// actually given. Everyone with a role may look; an operator may change.
    Infra,
    /// What lives inside a tenant: vms, images, volumes, floating addresses.
    /// The verb door is here, WHOSE object it is is `permits_object`.
    Tenant,
    /// Asking for a certificate — the renewal path. Not a privilege: the gate
    /// is the approval, which is `Directory`. K8s says the same thing.
    CsrCreate,
    /// A tenant's object that only an OPERATOR may write: `vmmigrations` and
    /// `routers`.
    ///
    /// The fifth class the comment above asked for, with its paragraph. A
    /// live migration is filed in a tenant — it is a record of what happened
    /// to their VM and they should be able to read it — but asking for one is
    /// running the estate, not using it: it is how an operator gets a machine
    /// empty, it costs a stream between two hosts, and a member who could
    /// start them could move their own VMs around somebody else's fleet all
    /// afternoon.
    ///
    /// So `Tenant` for the read half, `Infra` for the write half, which is
    /// exactly what "a move is an operation" means. Squeezing it into either
    /// of those two would have got one of the halves wrong.
    ///
    /// A `Router` is here by the same argument, one noun over: it is the
    /// tenant's way out and their business to read, and making one names the
    /// operator's provider network and takes a gateway slot on the operator's
    /// machines. A member who could create routers could fill every gateway
    /// node in the fleet an afternoon.
    TenantOperated,
}

/// Which class a resource falls in.
///
/// `certificatesigningrequests` is in two of them, and that split IS the
/// design: creating, reading and deleting your own request is `CsrCreate` and
/// open to anybody the directory knows, and saying yes to one is `Directory`
/// and an admin's. `classify` only ever produces `Verb::Approve` for the
/// `/approval` subresource, so the verb is enough to tell them apart.
pub fn class_of(resource: &str, verb: Verb) -> Class {
    match resource {
        Tenant::RESOURCE | User::RESOURCE => Class::Directory,
        CertificateSigningRequest::RESOURCE if verb == Verb::Approve => Class::Directory,
        CertificateSigningRequest::RESOURCE => Class::CsrCreate,
        // Before the tenant-scoped arm, and it has to be: a migration IS
        // tenant-scoped, and this is the half of that sentence the general
        // arm would get wrong. A router is the second of them.
        crate::resources::VmMigration::RESOURCE | crate::resources::Router::RESOURCE => {
            Class::TenantOperated
        }
        r if is_tenant_scoped(r) => Class::Tenant,
        // Everything else is the estate: clusters, nodes, storage pools,
        // floating pools, routed subnets, the provider networks a cluster
        // gave an interface away for — and the event log, which is a read of
        // what happened to the estate and is filtered by the handler for a
        // caller confined to one tenant.
        _ => Class::Infra,
    }
}

/// The least role that may do `verb` to something in `class`.
///
/// `None` is "nobody but `system:masters`", and it is what the two
/// unreachable cells of the table say: there is no approving a VM and no
/// approving a node.
///
/// This function IS the policy. Everything above it decides which cell to
/// look in and everything below it compares two roles.
pub fn least_role(class: Class, verb: Verb) -> Option<Role> {
    match (class, verb) {
        // Who exists, and who may say yes to a certificate. One answer.
        (Class::Directory, _) => Some(Role::Admin),
        // The renewal path: anybody the directory knows at all, which is the
        // lowest role there is.
        (Class::CsrCreate, Verb::Read | Verb::Write) => Some(Role::Viewer),
        (Class::CsrCreate, Verb::Approve) => None,
        (Class::Infra, Verb::Read) => Some(Role::Viewer),
        (Class::Infra, Verb::Write) => Some(Role::Operator),
        (Class::Tenant, Verb::Read) => Some(Role::Viewer),
        (Class::Tenant, Verb::Write) => Some(Role::Member),
        // The fifth class: read like a tenant's object, write like the
        // estate. See `Class::TenantOperated`.
        (Class::TenantOperated, Verb::Read) => Some(Role::Viewer),
        (Class::TenantOperated, Verb::Write) => Some(Role::Operator),
        // Approving is one act on one resource, and it is in `Directory`.
        (Class::Infra | Class::Tenant | Class::TenantOperated, Verb::Approve) => None,
    }
}

/// The verb half of the policy: may this caller do this KIND of thing at all.
///
/// A table since the roles became four: `class_of` says which cell,
/// `least_role` says what it costs, and the comparison is one `<`. The
/// `match` this replaced grew a branch per role per resource and could not be
/// read as a policy at all, which is how "system may do anything" survived in
/// it for four milestones.
///
/// `role` is what the caller could establish: the cloud reads it off the
/// `User` object, because the directory is the truth and a role change there
/// has to take effect at once; the cluster has no directory and passes what
/// the certificate claims. That difference is real and it is the price of the
/// design rule that there is one user directory in the stack — a role change
/// is instant at the cloud and takes effect at the cluster when the
/// certificate is re-issued.
///
/// `tenant` is the caller's, out of the same directory entry, and it is what
/// opens the write door for a member: a tenant-scoped write is allowed HERE
/// only so that `permits_object` can decide it THERE, against the object.
/// A tier that cannot establish a tenant — the cluster, which keeps no users
/// — passes `None`, and a member's writes are refused exactly as they were
/// before this milestone. That is not a gap left open: authorization needs
/// the directory, the directory is the cloud's, and a cluster inventing a
/// second answer to "whose VM is this" is the failure mode the one-directory
/// rule exists to prevent.
///
/// `own_peer` is the one system identity this router lets in besides
/// `system:masters`: the tier it IS, reading. See the `system:` block below.
/// A tier with no siblings passes `None`.
pub fn permits(
    identity: &Identity,
    role: Option<Role>,
    tenant: Option<&str>,
    attempt: &Attempt<'_>,
    own_peer: Option<OwnPeer<'_>>,
) -> bool {
    // Break glass is above the directory and above this table.
    if identity.has_group(GROUP_MASTERS) {
        return true;
    }
    if identity.is_system() {
        // Every other machine identity has NOTHING at REST, and that is the
        // change this table makes on purpose. `system:nodes` and
        // `system:clusters` speak the gRPC session, which is the only place
        // they need; a node's key used to be a key to every object of every
        // tenant through this door, for no purpose anybody could name.
        //
        // One exception, and it is what `vm logs` needs: a replica of this
        // same tier may READ here — a replica asking its sibling is the tier
        // asking itself.
        //
        // It takes the KIND as well as the name since the cloud grew the same
        // need. `system:cluster:cluster-1` at a cloud called `cluster-1`
        // would otherwise be a cluster reading the cloud's whole estate,
        // which is the door this table exists to shut.
        return match (own_peer, attempt.verb) {
            (Some(peer), Verb::Read) => identity.name == Identity::peer_name(peer.kind, peer.name),
            // And the write half, which is two named routes wide. See
            // `OwnPeer::forwarded` for why it is not the whole door.
            (Some(peer), Verb::Write) => {
                peer.forwarded
                    && forwardable_write(attempt)
                    && identity.name == Identity::peer_name(peer.kind, peer.name)
            }
            _ => false,
        };
    }
    // A valid certificate for somebody the directory does not know is not a
    // permission.
    let Some(role) = role else {
        return false;
    };
    let class = class_of(attempt.resource, attempt.verb);
    let Some(least) = least_role(class, attempt.verb) else {
        return false;
    };
    if role < least {
        return false;
    }
    // The one thing the table cannot say, because it is about the CALLER and
    // not about the resource: a tenant-scoped write needs an established
    // tenant to be scoped to. A tier that keeps no directory establishes
    // none, so a member there is read-only exactly as it was in M4.5 — see
    // the paragraph above.
    if class == Class::Tenant && attempt.verb == Verb::Write && role < Role::Operator {
        return tenant.is_some_and(|t| !t.is_empty());
    }
    true
}

/// The two routes a sibling may write through, and nothing else.
///
/// Named rather than inlined because it is a policy statement, and the two
/// entries are the same statement one tier apart: what a forwarded write may
/// reach is something whose write has to travel down a gRPC SESSION, which is
/// the only kind of write a replica cannot serve on its own. Every other
/// write at either tier goes into the shared store and any replica can do it,
/// so no other route needs this and no other route gets it.
///
///   * `clusters/<name>/nodes/<node>` — a `node cordon` or `node drain` at
///     the cloud, which travels down the cluster's session.
///   * `nodes/<name>/commands` — a live migration's command at the cluster,
///     which travels down the node's session. The one object this tier
///     reconciles that is about TWO machines, whose sessions can hang off two
///     replicas; see the cluster's `dispatch` module. The BODY of that route
///     is a closed enum of four migration commands, which is where the
///     narrowness actually lives — this table only says who may knock.
///   * `vmmigrations` at the CLOUD — `vm migrate` asked one tier up, which
///     travels down the CLUSTER's session as `CreateVmMigration`. It has the
///     same shape as the first entry and it was left out: the forward was
///     built for it and the door was not opened, so the verb worked only if
///     the caller happened to dial the replica holding that cluster's
///     session — one in three, and silently. Found in the lab, where it
///     answered "system:cloud:cloud may not Write vmmigrations".
fn forwardable_write(attempt: &Attempt<'_>) -> bool {
    let cluster_node = attempt.resource == crate::resources::Cluster::RESOURCE
        && attempt.subresource == Some("nodes");
    let node_command = attempt.resource == crate::resources::Node::RESOURCE
        && attempt.subresource == Some("commands");
    let vm_migration = attempt.resource == crate::resources::VmMigration::RESOURCE
        && attempt.subresource.is_none();
    cluster_node || node_command || vm_migration
}

/// The tier a router IS, for the one system identity it lets in besides break
/// glass: itself, reading.
///
/// Kind and name together, and the kind is not decoration. Both tiers issue
/// their identities through `Identity::peer_name`, so `system:cluster:acme`
/// and `system:cloud:acme` are two different certificates that differ in one
/// word — and a comparison that ignored the word would let a cluster read
/// everything a cloud holds the moment somebody named them alike.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnPeer<'a> {
    /// `"cluster"` or `"cloud"` — the middle word of the certificate's CN.
    pub kind: &'a str,
    /// This tier's own name: the cluster name, or the cloud name.
    pub name: &'a str,
    /// Whether this request carries `x-meister-forwarded` — a sibling passing
    /// on something a person asked it, once.
    ///
    /// It is what opens the WRITE door, and only for a node of a cluster.
    /// The reason the door is that narrow: a `node drain` at the cloud cannot
    /// be served by the replica that was asked, because it travels down the
    /// cluster's gRPC session and only one replica holds it — so two of every
    /// three `node cordon` calls answered 503 "no active session" and the
    /// client had to guess which replica to ask. Every other write at this
    /// tier goes into the shared store and any replica can do it, so no other
    /// route needs this and no other route gets it.
    ///
    /// The header is not a credential and is not treated as one: the caller
    /// still has to present this tier's own `system:<kind>:<name>`
    /// certificate, which nothing outside the control plane holds. What the
    /// header adds is that a sibling cannot be talked into a write by
    /// somebody who merely stole a look at the CA — a direct call with that
    /// identity and no header is refused exactly as it was before.
    pub forwarded: bool,
}

/// What a tenant-scoped object says about whose it is.
///
/// Both fields default to "nobody's": an object written before this milestone
/// carries neither, and a member may neither read nor write it. That is the
/// conservative direction of the two — the alternative, treating an unscoped
/// object as everybody's, would have made every VM in the lab visible to the
/// first member somebody created.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Scope<'a> {
    pub tenant: Option<&'a str>,
    /// Readable by every tenant. Images only; a VM is never public, and there
    /// is deliberately no field on one that could make it so.
    pub public: bool,
}

impl<'a> Scope<'a> {
    pub fn of(tenant: Option<&'a str>) -> Self {
        Self {
            tenant,
            public: false,
        }
    }

    pub fn image(tenant: Option<&'a str>, public: bool) -> Self {
        Self { tenant, public }
    }
}

/// The object half of the policy: may this caller do this to THIS object.
///
/// Runs in the handler rather than the middleware, and it has to: the
/// middleware sees a method and a path, and whose an object is is a fact
/// about the object. A handler that forgets to ask is the hole this design
/// has, which is why every one of them asks through this one function and why
/// the list handlers filter through it too — an object a member may not read
/// must not appear in a list either, or the name alone leaks the inventory.
pub fn permits_object(
    identity: &Identity,
    role: Option<Role>,
    caller_tenant: Option<&str>,
    scope: Scope<'_>,
    verb: Verb,
) -> bool {
    if identity.is_system() || role == Some(Role::Admin) {
        return true;
    }
    // Viewer, Member and Operator are all inside the tenancy, and the whole
    // difference between them is the VERB — which is `permits`' question,
    // asked before this one. Here the question is only whose the object is,
    // and it has the same answer for all three.
    let Some(role) = role else {
        return false;
    };
    let Some(mine) = caller_tenant.filter(|t| !t.is_empty()) else {
        return false;
    };
    let own = scope.tenant == Some(mine);
    match verb {
        // An operator reads every tenant's objects and a public image is
        // somebody else's object that everybody may boot from; neither is
        // somebody else's object that anybody may edit.
        //
        // The operator half is the same line `Grant::confined_to` draws one
        // tier up, said about ONE object rather than about a listing, and the
        // two have to agree: a listing that hands an operator every VM in the
        // cloud and a GET that refuses the one they clicked is an API that
        // contradicts itself in two requests. An estate you can see the names
        // of and not the objects of is not one you can run — and `logs` and
        // `events` hang off the same permission, which is the half an
        // operator actually needs at three in the morning.
        Verb::Read => role >= Role::Operator || own || scope.public,
        // Belt and braces with `permits`, which has already refused a viewer
        // this: a viewer sees its tenant and `public`, and writes nothing.
        Verb::Write => own && role >= Role::Member,
        Verb::Approve => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resources::{FloatingPool, RoutedSubnet, Tenant, User};

    fn member(name: &str) -> Identity {
        Identity::new(name, vec![GROUP_MEMBERS.into()])
    }

    /// `permits` with no sibling to let in, which is every tier but a
    /// cluster and every one of these cases. The exception has tests of its
    /// own below.
    fn allows(
        identity: &Identity,
        role: Option<Role>,
        tenant: Option<&str>,
        attempt: &Attempt<'_>,
    ) -> bool {
        permits(identity, role, tenant, attempt, None)
    }

    fn read(resource: &str) -> Attempt<'_> {
        Attempt {
            resource,
            subresource: None,
            verb: Verb::Read,
        }
    }
    fn write(resource: &str) -> Attempt<'_> {
        Attempt {
            resource,
            subresource: None,
            verb: Verb::Write,
        }
    }

    struct Never;
    impl Authenticator for Never {
        fn authenticate(&self, _: &AuthRequest) -> anyhow::Result<Option<Identity>> {
            Ok(None)
        }
    }
    struct Refuses;
    impl Authenticator for Refuses {
        fn authenticate(&self, _: &AuthRequest) -> anyhow::Result<Option<Identity>> {
            anyhow::bail!("checked, and no")
        }
    }
    struct Accepts(&'static str);
    impl Authenticator for Accepts {
        fn authenticate(&self, _: &AuthRequest) -> anyhow::Result<Option<Identity>> {
            Ok(Some(Identity::new(self.0, vec![])))
        }
    }

    /// The mode this stack ran in for four milestones, and the default.
    #[test]
    fn an_empty_chain_is_anonymous_and_anonymous_may_do_anything() {
        let chain = AuthChain::default();
        assert!(chain.is_empty());
        assert_eq!(
            chain.authenticate(&AuthRequest::default()).unwrap(),
            Authenticated::Anonymous
        );
    }

    #[test]
    fn the_first_link_that_recognises_the_request_wins() {
        let chain = AuthChain::new(vec![
            Box::new(Never),
            Box::new(Accepts("a")),
            Box::new(Accepts("b")),
        ]);
        let who = chain.authenticate(&AuthRequest::default()).unwrap();
        assert_eq!(who, Authenticated::As(Identity::new("a", vec![])));
    }

    /// The rule the chain exists to keep: a weaker authenticator behind a
    /// stronger one must not be able to say yes after it said no.
    #[test]
    fn a_hard_no_ends_the_chain() {
        let chain = AuthChain::new(vec![Box::new(Refuses), Box::new(Accepts("smuggled"))]);
        let err = chain.authenticate(&AuthRequest::default()).unwrap_err();
        assert!(err.to_string().contains("checked, and no"), "{err}");
    }

    /// A non-empty chain that nobody claimed is a 401, not an anonymous pass.
    #[test]
    fn a_configured_chain_that_recognises_nothing_refuses() {
        let chain = AuthChain::new(vec![Box::new(Never)]);
        assert!(chain.authenticate(&AuthRequest::default()).is_err());
    }

    #[test]
    fn the_dev_bearer_token_recognises_exactly_its_own_token() {
        let auth = BearerAuthenticator::new(
            "s3cret",
            Identity::new("dev-admin", vec![GROUP_ADMINS.into()]),
        );
        // No header at all: not our business.
        assert!(
            auth.authenticate(&AuthRequest::default())
                .unwrap()
                .is_none()
        );
        // Another scheme: also not our business — mTLS may still answer.
        let other = AuthRequest {
            authorization: Some("Basic aGk6dGhlcmU=".into()),
            ..Default::default()
        };
        assert!(auth.authenticate(&other).unwrap().is_none());
        // Ours and right.
        let good = AuthRequest {
            authorization: Some("Bearer s3cret".into()),
            ..Default::default()
        };
        assert_eq!(auth.authenticate(&good).unwrap().unwrap().name, "dev-admin");
        // Ours and wrong: a refusal, not a pass.
        let bad = AuthRequest {
            authorization: Some("Bearer nope".into()),
            ..Default::default()
        };
        assert!(auth.authenticate(&bad).is_err());
    }

    #[test]
    fn health_probes_are_not_api_objects_and_are_never_gated() {
        assert!(classify("GET", "/healthz").is_none());
        // Still ungated now that it does real work: a probe that needed a
        // certificate could not tell "down" from "not invited", and the whole
        // value of readiness is that a load balancer can ask it.
        assert!(classify("GET", "/readyz").is_none());
    }

    #[test]
    fn a_request_is_classified_by_its_path_and_method() {
        assert_eq!(
            classify("GET", "/apis/meister.io/v1/vms").unwrap(),
            Attempt {
                resource: "vms",
                subresource: None,
                verb: Verb::Read
            }
        );
        assert_eq!(
            classify("GET", "/apis/meister.io/v1/vms?watch=1")
                .unwrap()
                .resource,
            "vms"
        );
        assert_eq!(
            classify("DELETE", "/apis/meister.io/v1/vms/web-1")
                .unwrap()
                .verb,
            Verb::Write
        );
        assert_eq!(
            classify("PUT", "/apis/meister.io/v1/vms/web-1/status")
                .unwrap()
                .verb,
            Verb::Write
        );
        let approval = classify(
            "PUT",
            "/apis/meister.io/v1/certificatesigningrequests/x/approval",
        )
        .unwrap();
        assert_eq!(approval.verb, Verb::Approve);
        assert_eq!(approval.subresource, Some("approval"));
    }

    #[test]
    fn a_member_writes_inside_its_tenant_and_reads_beyond_it() {
        let m = member("alice");
        let t = Some("acme");
        assert!(allows(&m, Some(Role::Member), t, &read("vms")));
        assert!(allows(&m, Some(Role::Member), t, &write("vms")));
        assert!(allows(&m, Some(Role::Member), t, &write(Image::RESOURCE)));
        assert!(allows(
            &m,
            Some(Role::Member),
            t,
            &write(CertificateSigningRequest::RESOURCE)
        ));
        // Everything else is still an admin's: a member may look at the user
        // directory and at the clusters, and may not write either.
        assert!(!allows(&m, Some(Role::Member), t, &write(User::RESOURCE)));
        assert!(!allows(&m, Some(Role::Member), t, &write(Tenant::RESOURCE)));
        assert!(!allows(
            &m,
            Some(Role::Member),
            t,
            &Attempt {
                resource: CertificateSigningRequest::RESOURCE,
                subresource: Some("approval"),
                verb: Verb::Approve
            }
        ));
    }

    /// The assignment rule of the network half, at the verb level: what
    /// EXISTS — the pools an operator was given, the subnets an operator
    /// carved — is an administrator's, and taking one address out of a pool
    /// is self-service. The quota behind that door is what bounds it, and a
    /// public pool's quota is zero.
    #[test]
    fn a_member_takes_addresses_but_never_makes_pools_or_subnets() {
        let m = member("alice");
        let t = Some("acme");
        assert!(allows(
            &m,
            Some(Role::Member),
            t,
            &write(FloatingIp::RESOURCE)
        ));
        assert!(allows(
            &m,
            Some(Role::Member),
            t,
            &read(FloatingPool::RESOURCE)
        ));
        assert!(allows(
            &m,
            Some(Role::Member),
            t,
            &read(RoutedSubnet::RESOURCE)
        ));
        assert!(!allows(
            &m,
            Some(Role::Member),
            t,
            &write(FloatingPool::RESOURCE)
        ));
        assert!(!allows(
            &m,
            Some(Role::Member),
            t,
            &write(RoutedSubnet::RESOURCE)
        ));

        let admin = Identity::new("root", vec![GROUP_ADMINS.into()]);
        assert!(allows(
            &admin,
            Some(Role::Admin),
            None,
            &write(FloatingPool::RESOURCE)
        ));
        assert!(allows(
            &admin,
            Some(Role::Admin),
            None,
            &write(RoutedSubnet::RESOURCE)
        ));
    }

    /// And at the object level: a reservation is its tenant's, and a routed
    /// subnet is visible to the tenant it was cut for and to nobody else.
    #[test]
    fn one_tenants_addresses_are_invisible_to_another() {
        let m = member("alice");
        let mine = Scope::of(Some("acme"));
        let theirs = Scope::of(Some("globex"));
        assert!(permits_object(
            &m,
            Some(Role::Member),
            Some("acme"),
            mine,
            Verb::Read
        ));
        assert!(permits_object(
            &m,
            Some(Role::Member),
            Some("acme"),
            mine,
            Verb::Write
        ));
        assert!(!permits_object(
            &m,
            Some(Role::Member),
            Some("acme"),
            theirs,
            Verb::Read
        ));
        assert!(!permits_object(
            &m,
            Some(Role::Member),
            Some("acme"),
            theirs,
            Verb::Write
        ));
    }

    /// The cluster tier, which keeps no users and so can establish no tenant.
    /// A member there is exactly what a member was in M4.5: read-only. The
    /// scoping needs the directory, and the directory is the cloud's.
    #[test]
    fn a_member_without_an_established_tenant_may_still_only_read() {
        let m = member("alice");
        assert!(allows(&m, Some(Role::Member), None, &read("vms")));
        assert!(!allows(&m, Some(Role::Member), None, &write("vms")));
        assert!(!allows(&m, Some(Role::Member), Some(""), &write("vms")));
        // The renewal path is not tenant-scoped and stays open.
        assert!(allows(
            &m,
            Some(Role::Member),
            None,
            &write(CertificateSigningRequest::RESOURCE)
        ));
    }

    #[test]
    fn an_admin_may_do_everything_and_a_stranger_nothing() {
        let admin = Identity::new("root", vec![GROUP_ADMINS.into()]);
        assert!(allows(&admin, Some(Role::Admin), None, &write("vms")));
        assert!(allows(
            &admin,
            Some(Role::Admin),
            None,
            &Attempt {
                resource: CertificateSigningRequest::RESOURCE,
                subresource: Some("approval"),
                verb: Verb::Approve
            }
        ));

        // Authenticated but in nobody's directory: a valid certificate is not
        // by itself a permission.
        let stranger = Identity::new("mallory", vec![]);
        assert!(!allows(&stranger, None, None, &read("vms")));
        assert!(!allows(
            &stranger,
            None,
            None,
            &write(CertificateSigningRequest::RESOURCE)
        ));
    }

    /// The whole table, one assertion per cell.
    ///
    /// Written out rather than derived from `least_role`, which is the point:
    /// a test that computed the answer the same way the code does would pass
    /// whatever the policy said. This is the policy, spelled a second time by
    /// hand, and a change to `least_role` has to be made here too.
    #[test]
    fn every_cell_of_the_permission_table() {
        use Role::{Admin, Member, Operator, Viewer};
        let by_role = |cases: &[(Role, &str, Verb, bool)]| {
            for (role, resource, verb, expected) in cases {
                let identity = Identity::new("someone", vec![role.group().to_string()]);
                let attempt = Attempt {
                    resource,
                    subresource: if *verb == Verb::Approve {
                        Some("approval")
                    } else {
                        None
                    },
                    verb: *verb,
                };
                assert_eq!(
                    allows(&identity, Some(*role), Some("acme"), &attempt),
                    *expected,
                    "{} {verb:?} {resource}",
                    role.as_str()
                );
            }
        };

        // Directory: who exists and what they may do. An admin's, all of it.
        by_role(&[
            (Viewer, "tenants", Verb::Read, false),
            (Member, "tenants", Verb::Read, false),
            (Operator, "tenants", Verb::Read, false),
            (Admin, "tenants", Verb::Read, true),
            (Operator, "tenants", Verb::Write, false),
            (Admin, "tenants", Verb::Write, true),
            (Operator, "users", Verb::Read, false),
            (Admin, "users", Verb::Write, true),
            // Approving a certificate request is the one write that hands out
            // a credential, and it is nobody's but an admin's.
            (Viewer, "certificatesigningrequests", Verb::Approve, false),
            (Member, "certificatesigningrequests", Verb::Approve, false),
            (Operator, "certificatesigningrequests", Verb::Approve, false),
            (Admin, "certificatesigningrequests", Verb::Approve, true),
        ]);

        // CsrCreate: the renewal path. Anybody the directory knows at all.
        by_role(&[
            (Viewer, "certificatesigningrequests", Verb::Read, true),
            (Viewer, "certificatesigningrequests", Verb::Write, true),
            (Member, "certificatesigningrequests", Verb::Write, true),
            (Operator, "certificatesigningrequests", Verb::Write, true),
            (Admin, "certificatesigningrequests", Verb::Write, true),
        ]);

        // Infra: the estate. Everyone looks, an operator changes.
        for resource in [
            "clusters",
            "nodes",
            "storagepools",
            "floatingpools",
            "routedsubnets",
            "providernetworks",
            "events",
        ] {
            by_role(&[
                (Viewer, resource, Verb::Read, true),
                (Member, resource, Verb::Read, true),
                (Operator, resource, Verb::Read, true),
                (Admin, resource, Verb::Read, true),
                (Viewer, resource, Verb::Write, false),
                (Member, resource, Verb::Write, false),
                (Operator, resource, Verb::Write, true),
                (Admin, resource, Verb::Write, true),
            ]);
        }

        // Tenant: what lives inside one. Everyone looks, a member changes —
        // and WHICH objects is `permits_object`, further down.
        for resource in ["vms", "images", "volumes", "floatingips"] {
            by_role(&[
                (Viewer, resource, Verb::Read, true),
                (Member, resource, Verb::Read, true),
                (Operator, resource, Verb::Read, true),
                (Admin, resource, Verb::Read, true),
                (Viewer, resource, Verb::Write, false),
                (Member, resource, Verb::Write, true),
                (Operator, resource, Verb::Write, true),
                (Admin, resource, Verb::Write, true),
            ]);
        }

        // TenantOperated: read like a tenant's object, write like the estate.
        // The two of them, and the split is the whole class — a member sees
        // whether their router is up and cannot make one, because a router
        // takes a gateway slot on the operator's machines.
        for resource in ["vmmigrations", "routers"] {
            by_role(&[
                (Viewer, resource, Verb::Read, true),
                (Member, resource, Verb::Read, true),
                (Operator, resource, Verb::Read, true),
                (Admin, resource, Verb::Read, true),
                (Viewer, resource, Verb::Write, false),
                (Member, resource, Verb::Write, false),
                (Operator, resource, Verb::Write, true),
                (Admin, resource, Verb::Write, true),
            ]);
        }

        // And there is no approving anything but a certificate request.
        for resource in ["vms", "nodes", "clusters"] {
            by_role(&[
                (Admin, resource, Verb::Approve, false),
                (Operator, resource, Verb::Approve, false),
            ]);
        }
    }

    /// The order the whole table hangs off. Nailed here because reordering
    /// the variants would otherwise change the policy in silence.
    #[test]
    fn the_four_roles_run_viewer_member_operator_admin() {
        use Role::{Admin, Member, Operator, Viewer};
        assert!(Viewer < Member);
        assert!(Member < Operator);
        assert!(Operator < Admin);
        let mut sorted = Role::ALL;
        sorted.sort();
        assert_eq!(sorted, [Viewer, Member, Operator, Admin]);
        // ALL itself runs the other way — most to least — because
        // `from_groups` reads it as a precedence list.
        assert_eq!(Role::ALL, [Admin, Operator, Member, Viewer]);
        assert_eq!(
            Role::from_groups(&[GROUP_VIEWERS.into(), GROUP_OPERATORS.into()]),
            Some(Operator),
            "the highest a certificate claims is the one that counts"
        );
    }

    /// The two new roles, in the words an operator would use.
    #[test]
    fn an_operator_drains_machines_and_a_viewer_only_looks() {
        let ops = Identity::new("olivia", vec![GROUP_OPERATORS.into()]);
        assert!(allows(&ops, Some(Role::Operator), None, &write("nodes")));
        assert!(allows(
            &ops,
            Some(Role::Operator),
            None,
            &write("storagepools")
        ));
        assert!(!allows(&ops, Some(Role::Operator), None, &write("tenants")));
        assert!(!allows(&ops, Some(Role::Operator), None, &write("users")));
        assert!(!allows(
            &ops,
            Some(Role::Operator),
            None,
            &Attempt {
                resource: CertificateSigningRequest::RESOURCE,
                subresource: Some("approval"),
                verb: Verb::Approve
            }
        ));

        let view = Identity::new("val", vec![GROUP_VIEWERS.into()]);
        assert!(allows(
            &view,
            Some(Role::Viewer),
            Some("acme"),
            &read("vms")
        ));
        assert!(allows(
            &view,
            Some(Role::Viewer),
            Some("acme"),
            &read("nodes")
        ));
        assert!(!allows(
            &view,
            Some(Role::Viewer),
            Some("acme"),
            &write("vms")
        ));
        assert!(!allows(
            &view,
            Some(Role::Viewer),
            Some("acme"),
            &write("nodes")
        ));
    }

    /// And at the object level a viewer is scoped exactly as a member is: its
    /// own tenant and `public`, and nothing at all to write.
    #[test]
    fn a_viewer_sees_its_own_tenant_and_public_and_writes_nothing() {
        let view = Identity::new("val", vec![GROUP_VIEWERS.into()]);
        let mine = Scope::of(Some("acme"));
        let theirs = Scope::of(Some("globex"));
        let shared = Scope::image(Some("ops"), true);
        let seen =
            |scope, verb| permits_object(&view, Some(Role::Viewer), Some("acme"), scope, verb);

        assert!(seen(mine, Verb::Read));
        assert!(seen(shared, Verb::Read));
        assert!(!seen(theirs, Verb::Read));
        assert!(!seen(mine, Verb::Write), "not even its own");
        assert!(!seen(shared, Verb::Write));
    }

    /// The change this table makes on purpose, and the one existing test it
    /// breaks: a machine identity has NOTHING at REST.
    ///
    /// `system:nodes` and `system:clusters` speak the gRPC session, which is
    /// the only door they need. Until now a node's key was a key to every
    /// object of every tenant through this one, for no purpose anybody could
    /// name.
    #[test]
    fn a_machine_identity_has_nothing_at_rest_except_break_glass() {
        let node = Identity::new("system:node:manacor", vec![GROUP_NODES.into()]);
        assert!(node.is_system());
        for attempt in [read("vms"), write("vms"), read("nodes")] {
            assert!(!allows(&node, None, None, &attempt), "{attempt:?}");
            // and a cluster tier that lets a SIBLING in does not let a node in
            assert!(!permits(
                &node,
                None,
                None,
                &attempt,
                Some(OwnPeer {
                    kind: "cluster",
                    name: "cluster-1",
                    forwarded: false,
                })
            ));
        }

        // Break glass is above the directory and above this table.
        let masters = Identity::new("root", vec![GROUP_MASTERS.into()]);
        for attempt in [
            read("vms"),
            write("tenants"),
            Attempt {
                resource: CertificateSigningRequest::RESOURCE,
                subresource: Some("approval"),
                verb: Verb::Approve,
            },
        ] {
            assert!(allows(&masters, None, None, &attempt), "{attempt:?}");
        }
    }

    /// The one exception: a replica asking its sibling is the tier asking
    /// itself. Reading only, only its own name — and, since the cloud grew
    /// the same forward, only its own KIND.
    #[test]
    fn a_replica_of_this_tier_may_read_here_and_no_other_peer_may() {
        let c1 = Identity::new("system:cluster:cluster-1", vec![GROUP_CLUSTERS.into()]);
        let c2 = Identity::new("system:cluster:cluster-2", vec![GROUP_CLUSTERS.into()]);
        let here = Some(OwnPeer {
            kind: "cluster",
            name: "cluster-1",
            forwarded: false,
        });

        assert!(permits(&c1, None, None, &read("vms"), here));
        assert!(!permits(&c1, None, None, &write("vms"), here), "read only");
        assert!(
            !permits(&c2, None, None, &read("vms"), here),
            "another cluster"
        );
        // A tier that passes no sibling at all lets neither in.
        assert!(!allows(&c1, None, None, &read("vms")));

        // The cloud, one scope up, with the same rule and its own word.
        let cloud = Identity::new("system:cloud:lab", vec![GROUP_CLOUDS.into()]);
        let at_the_cloud = Some(OwnPeer {
            kind: "cloud",
            name: "lab",
            forwarded: false,
        });
        assert!(permits(&cloud, None, None, &read("vms"), at_the_cloud));
        assert!(!permits(&cloud, None, None, &write("vms"), at_the_cloud));

        // And the kind is not decoration: a CLUSTER called `lab` is not a
        // cloud called `lab`, however alike an operator named them.
        let namesake = Identity::new("system:cluster:lab", vec![GROUP_CLUSTERS.into()]);
        assert!(
            !permits(&namesake, None, None, &read("vms"), at_the_cloud),
            "one word apart is still somebody else"
        );
    }

    /// D2's other half: the one WRITE a sibling may pass on, and everything
    /// it may not.
    ///
    /// A node patch at the cloud does not go into the shared store — it
    /// travels down the cluster's gRPC session, and only one replica holds
    /// it. So `node cordon` answered 503 on two of three replicas and the
    /// client had to guess. The door this opens is exactly one route wide,
    /// and it needs both halves: this tier's own certificate, which nothing
    /// outside the control plane holds, AND the forward header.
    #[test]
    fn a_sibling_may_pass_on_a_node_patch_and_nothing_else() {
        let cloud = Identity::new("system:cloud:lab", vec![GROUP_CLOUDS.into()]);
        let node_of_a_cluster = Attempt {
            resource: crate::resources::Cluster::RESOURCE,
            subresource: Some("nodes"),
            verb: Verb::Write,
        };
        let forwarded = Some(OwnPeer {
            kind: "cloud",
            name: "lab",
            forwarded: true,
        });
        let direct = Some(OwnPeer {
            kind: "cloud",
            name: "lab",
            forwarded: false,
        });

        assert!(permits(&cloud, None, None, &node_of_a_cluster, forwarded));
        assert!(
            !permits(&cloud, None, None, &node_of_a_cluster, direct),
            "the header is what says a person asked for this, once"
        );

        // The third route of this table, and the one the lab found missing:
        // `vm migrate` asked at the cloud travels down the CLUSTER's session
        // as CreateVmMigration, so it is the node patch's shape exactly. The
        // forward was built for it and the door was not opened, so the verb
        // worked on one replica in three and answered
        // "system:cloud:cloud may not Write vmmigrations" on the other two.
        let a_migration = Attempt {
            resource: crate::resources::VmMigration::RESOURCE,
            subresource: None,
            verb: Verb::Write,
        };
        assert!(permits(&cloud, None, None, &a_migration, forwarded));
        assert!(
            !permits(&cloud, None, None, &a_migration, direct),
            "and the same header rule: a sibling passes on what a person asked, once"
        );

        // Every other write stays shut, header or no header. The reason the
        // door is this narrow is that no other write at this tier needs it:
        // everything else goes into the store, and any replica can do it.
        for attempt in [
            write("vms"),
            write("clusters"),
            write("tenants"),
            write("storagepools"),
            Attempt {
                resource: crate::resources::Cluster::RESOURCE,
                subresource: None,
                verb: Verb::Write,
            },
        ] {
            assert!(
                !permits(&cloud, None, None, &attempt, forwarded),
                "{attempt:?} is not the node route"
            );
        }

        // And it is still this tier's own certificate or nothing: a cluster,
        // or a cloud by another name, is refused with the header in hand.
        let other = Identity::new("system:cloud:other", vec![GROUP_CLOUDS.into()]);
        assert!(!permits(&other, None, None, &node_of_a_cluster, forwarded));
        let cluster = Identity::new("system:cluster:lab", vec![GROUP_CLUSTERS.into()]);
        assert!(!permits(
            &cluster,
            None,
            None,
            &node_of_a_cluster,
            forwarded
        ));

        // A node's key opens nothing here, which is the rule this table was
        // written to state.
        let node = Identity::new("system:node:agent-1a", vec![GROUP_NODES.into()]);
        assert!(!permits(&node, None, None, &node_of_a_cluster, forwarded));
    }

    /// The second forwarded write, one tier down (D-P2): a live migration is
    /// the one object at the cluster whose commands have to reach two nodes,
    /// and their sessions can hang off two replicas.
    ///
    /// The same three rules as the node patch above — this tier's own
    /// certificate, the header, and that one route — because it is the same
    /// door with a second entry and not a second door.
    #[test]
    fn a_sibling_may_pass_on_a_migration_command_and_still_nothing_else() {
        let cluster = Identity::new("system:cluster:cluster-1", vec![GROUP_CLUSTERS.into()]);
        let command = Attempt {
            resource: crate::resources::Node::RESOURCE,
            subresource: Some("commands"),
            verb: Verb::Write,
        };
        let peer = |forwarded| {
            Some(OwnPeer {
                kind: "cluster",
                name: "cluster-1",
                forwarded,
            })
        };

        assert!(permits(&cluster, None, None, &command, peer(true)));
        assert!(
            !permits(&cluster, None, None, &command, peer(false)),
            "a direct call with that certificate is refused exactly as it was"
        );

        // A node's own key is the one that would matter if this were open,
        // and it is not: an agent that reached this route could tell another
        // agent to destroy a guest.
        let node = Identity::new("system:node:agent-1a", vec![GROUP_NODES.into()]);
        assert!(!permits(&node, None, None, &command, peer(true)));
        // Nor a cloud, nor a cluster by another name.
        let other = Identity::new("system:cluster:other", vec![GROUP_CLUSTERS.into()]);
        assert!(!permits(&other, None, None, &command, peer(true)));

        // And the write half of the node route itself stays shut: a node's
        // SPEC is a store write that any replica can do.
        let spec = Attempt {
            resource: crate::resources::Node::RESOURCE,
            subresource: None,
            verb: Verb::Write,
        };
        assert!(!permits(&cluster, None, None, &spec, peer(true)));

        // The path classifies the way the rule assumes it does.
        let attempt =
            classify("POST", "/apis/meister.io/v1/nodes/agent-1a/commands").expect("an api route");
        assert_eq!(attempt.resource, crate::resources::Node::RESOURCE);
        assert_eq!(attempt.subresource, Some("commands"));
        assert_eq!(attempt.verb, Verb::Write);
    }

    /// And the path really does classify the way the rule assumes. A rule
    /// written against `resource`/`subresource` that `classify` never
    /// produces would be a door that is open and unreachable, or shut and
    /// believed open.
    #[test]
    fn a_node_patch_classifies_as_a_write_on_a_cluster_subresource() {
        let attempt = classify(
            "PATCH",
            "/apis/meister.io/v1/clusters/cluster-1/nodes/agent-1a",
        )
        .expect("an api route");
        assert_eq!(attempt.resource, crate::resources::Cluster::RESOURCE);
        assert_eq!(attempt.subresource, Some("nodes"));
        assert_eq!(attempt.verb, Verb::Write);
        // The read of the same path is a read, and needs no header at all.
        let read =
            classify("GET", "/apis/meister.io/v1/clusters/cluster-1/nodes").expect("a route");
        assert_eq!(read.verb, Verb::Read);
    }

    // --- the object half: whose object is it -------------------------------

    /// The matrix the E2E walks with a CLI, here with no processes in it.
    #[test]
    fn a_member_sees_and_touches_its_own_tenants_objects_and_no_others() {
        let alice = member("alice");
        let mine = Scope::of(Some("acme"));
        let theirs = Scope::of(Some("globex"));
        let nobodys = Scope::default();

        for verb in [Verb::Read, Verb::Write] {
            assert!(
                permits_object(&alice, Some(Role::Member), Some("acme"), mine, verb),
                "own object, {verb:?}"
            );
            assert!(
                !permits_object(&alice, Some(Role::Member), Some("acme"), theirs, verb),
                "another tenant's object, {verb:?}"
            );
            // An object written before tenants existed belongs to nobody, and
            // "nobody's" is the conservative reading: an admin's to see.
            assert!(
                !permits_object(&alice, Some(Role::Member), Some("acme"), nobodys, verb),
                "unscoped object, {verb:?}"
            );
        }
    }

    /// A public image is somebody else's object every tenant may boot from —
    /// and nobody else's to edit. The two halves are the whole point of the
    /// flag: without the read half every tenant needs its own catalogue entry
    /// for the same file, and without the write half `--public` would be a
    /// way to hand an image to anybody who asks.
    #[test]
    fn a_public_image_is_readable_by_every_tenant_and_writable_by_its_own() {
        let alice = member("alice");
        let shared = Scope::image(Some("ops"), true);
        assert!(permits_object(
            &alice,
            Some(Role::Member),
            Some("acme"),
            shared,
            Verb::Read
        ));
        assert!(!permits_object(
            &alice,
            Some(Role::Member),
            Some("acme"),
            shared,
            Verb::Write
        ));

        let ops = member("olivia");
        assert!(permits_object(
            &ops,
            Some(Role::Member),
            Some("ops"),
            shared,
            Verb::Write
        ));
    }

    /// The line an operator's job is drawn at: every object's CONTENTS, and
    /// only its own tenant's WRITES.
    ///
    /// It is `Grant::confined_to`'s line, said about one object. Before this,
    /// a listing showed an operator every VM in the cloud and the GET on any
    /// one of them was a 403 — the API contradicting itself in two requests,
    /// and `logs` and `events` refused along with it. Read is where an
    /// operator's job lives; write stays where a tenant boundary is worth
    /// something.
    #[test]
    fn an_operator_reads_every_tenants_objects_and_writes_only_its_own() {
        let olivia = Identity::new("olivia", vec![GROUP_OPERATORS.into()]);
        let mine = Scope::of(Some("acme"));
        let theirs = Scope::of(Some("globex"));
        // An object written before tenancy existed belongs to nobody, and an
        // operator reads that too: it is inventory, and unreadable inventory
        // is the thing that cannot be cleaned up.
        let nobodys = Scope::default();

        for (scope, what) in [
            (mine, "its own"),
            (theirs, "another's"),
            (nobodys, "nobody's"),
        ] {
            assert!(
                permits_object(
                    &olivia,
                    Some(Role::Operator),
                    Some("acme"),
                    scope,
                    Verb::Read
                ),
                "an operator reads {what} object"
            );
        }
        assert!(permits_object(
            &olivia,
            Some(Role::Operator),
            Some("acme"),
            mine,
            Verb::Write
        ));
        assert!(
            !permits_object(
                &olivia,
                Some(Role::Operator),
                Some("acme"),
                theirs,
                Verb::Write
            ),
            "reading the estate is not editing it"
        );

        // Unchanged below the line: a member still sees one room.
        let alice = member("alice");
        assert!(!permits_object(
            &alice,
            Some(Role::Member),
            Some("acme"),
            theirs,
            Verb::Read
        ));
        assert!(!permits_object(
            &alice,
            Some(Role::Viewer),
            Some("acme"),
            theirs,
            Verb::Read
        ));
    }

    /// Admins and the stack's own machinery are above the scoping, and a
    /// caller the directory does not know is below everything.
    #[test]
    fn admins_and_system_identities_are_not_scoped_and_strangers_have_nothing() {
        let theirs = Scope::of(Some("globex"));
        let admin = Identity::new("root", vec![GROUP_ADMINS.into()]);
        assert!(permits_object(
            &admin,
            Some(Role::Admin),
            None,
            theirs,
            Verb::Write
        ));

        let node = Identity::new("system:node:manacor", vec![GROUP_NODES.into()]);
        assert!(permits_object(&node, None, None, theirs, Verb::Write));

        let stranger = Identity::new("mallory", vec![]);
        assert!(!permits_object(
            &stranger,
            None,
            Some("globex"),
            theirs,
            Verb::Read
        ));

        // A member the directory puts in no tenant at all has nothing either.
        let orphan = member("nobody");
        assert!(!permits_object(
            &orphan,
            Some(Role::Member),
            None,
            theirs,
            Verb::Read
        ));
        assert!(!permits_object(
            &orphan,
            Some(Role::Member),
            Some(""),
            Scope::default(),
            Verb::Read
        ));
    }

    #[test]
    fn a_specific_peer_certificate_may_only_speak_for_that_peer() {
        let manacor = Identity::new("system:node:manacor", vec![GROUP_NODES.into()]);
        assert!(manacor.may_speak_for("node", "manacor"));
        assert!(!manacor.may_speak_for("node", "manacor-b"));
        // A shared tier certificate carries no peer name and speaks for any.
        let shared = Identity::new("agents", vec![GROUP_NODES.into()]);
        assert!(shared.may_speak_for("node", "manacor-b"));
    }

    /// The kind is half of the name. One CA signs nodes and clusters both,
    /// and the cloud's session port trusts that CA — so a check that only
    /// compared within a kind made every node's key a key to the cloud
    /// session of any cluster, under a name the cloud would then log as the
    /// cluster's.
    #[test]
    fn a_node_certificate_may_not_speak_for_a_cluster() {
        let node = Identity::new("system:node:manacor", vec![GROUP_NODES.into()]);
        assert!(!node.may_speak_for("cluster", "manacor"), "same name");
        assert!(!node.may_speak_for("cluster", "cluster-1"), "any name");

        let cluster = Identity::new("system:cluster:cluster-1", vec![GROUP_CLUSTERS.into()]);
        assert!(cluster.may_speak_for("cluster", "cluster-1"));
        assert!(!cluster.may_speak_for("node", "cluster-1"), "and back");

        // Still unchanged: a name that names no peer at all. `system:masters`
        // is the one that matters — break glass has no tier and must keep
        // working.
        let masters = Identity::new("system:masters", vec![GROUP_MASTERS.into()]);
        assert!(masters.may_speak_for("node", "manacor"));
    }

    // --- the mTLS authenticator, against real certificates ------------------

    /// A CA and one leaf signed by it, entirely in memory. Real DER, real
    /// signatures: the point of these tests is that the checking is real, and
    /// a hand-built fixture would only prove the parser runs.
    fn ca_and_leaf(
        cn: &str,
        org: Option<&str>,
        lifetime_days: i64,
    ) -> (Vec<CertificateDer<'static>>, Vec<u8>) {
        use rcgen::{
            BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose,
        };

        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "meister-ca");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let issuer = Issuer::new(ca_params, ca_key);

        let leaf_key = KeyPair::generate().unwrap();
        let mut leaf = CertificateParams::new(Vec::new()).unwrap();
        leaf.distinguished_name.push(DnType::CommonName, cn);
        if let Some(org) = org {
            leaf.distinguished_name.push(DnType::OrganizationName, org);
        }
        let epoch = Utc::now().timestamp();
        leaf.not_before = time::OffsetDateTime::from_unix_timestamp(epoch - 60).unwrap();
        leaf.not_after =
            time::OffsetDateTime::from_unix_timestamp(epoch + lifetime_days * 86_400).unwrap();
        let leaf = leaf.signed_by(&leaf_key, &issuer).unwrap();

        (vec![ca_cert.der().clone()], leaf.der().to_vec())
    }

    #[test]
    fn a_certificate_from_our_ca_is_a_name_and_its_groups() {
        let (cas, leaf) = ca_and_leaf("alice", Some(GROUP_MEMBERS), 90);
        let auth = MtlsAuthenticator::new(cas);
        let who = auth
            .authenticate_at(&AuthRequest::with_certs(vec![leaf]), Utc::now())
            .unwrap()
            .expect("recognised");
        assert_eq!(who.name, "alice");
        assert_eq!(who.claimed_role(), Some(Role::Member));
        assert!(!who.is_system());
    }

    /// The two ways a certificate can be wrong are told apart on purpose:
    /// "expired" is an operator's problem with a known fix, "no configured CA
    /// signed this" is somebody presenting a credential from somewhere else.
    #[test]
    fn an_expired_certificate_and_a_foreign_one_are_refused_for_different_reasons() {
        let now = Utc::now();
        let (cas, leaf) = ca_and_leaf("alice", Some(GROUP_MEMBERS), 1);
        let auth = MtlsAuthenticator::new(cas);
        let req = AuthRequest::with_certs(vec![leaf]);

        let expired = auth
            .authenticate_at(&req, now + chrono::Duration::days(2))
            .unwrap_err()
            .to_string();
        assert!(expired.contains("expired"), "{expired}");

        let (other_ca, _) = ca_and_leaf("mallory", None, 90);
        let foreign = MtlsAuthenticator::new(other_ca)
            .authenticate_at(&req, now)
            .unwrap_err()
            .to_string();
        assert!(foreign.contains("no configured CA"), "{foreign}");
    }

    /// No certificate is not a refusal: the request may be carrying a bearer
    /// token for the next link, and refusing here would end the chain.
    #[test]
    fn no_client_certificate_passes_to_the_next_link() {
        let (cas, _) = ca_and_leaf("alice", None, 90);
        let auth = MtlsAuthenticator::new(cas);
        assert!(
            auth.authenticate(&AuthRequest::default())
                .unwrap()
                .is_none()
        );
    }

    /// The whole chain as it is actually configured: a certificate wins, a
    /// token behind it still serves the bootstrap case, and a bad certificate
    /// is not rescued by a good token.
    #[test]
    fn the_configured_chain_is_mtls_then_the_dev_token() {
        let (cas, leaf) = ca_and_leaf("alice", Some(GROUP_MEMBERS), 90);
        let chain = AuthChain::new(vec![
            Box::new(MtlsAuthenticator::new(cas)),
            Box::new(BearerAuthenticator::new(
                "devtoken",
                Identity::new("dev-admin", vec![GROUP_ADMINS.into()]),
            )),
        ]);

        // Certificate: mTLS answers first.
        let with_cert = AuthRequest {
            peer_certs: vec![leaf.clone()],
            authorization: Some("Bearer devtoken".into()),
        };
        assert_eq!(
            chain.authenticate(&with_cert).unwrap(),
            Authenticated::As(Identity::new("alice", vec![GROUP_MEMBERS.into()]))
        );

        // No certificate: the token is the bootstrap path.
        let token_only = AuthRequest {
            peer_certs: vec![],
            authorization: Some("Bearer devtoken".into()),
        };
        assert_eq!(
            chain.authenticate(&token_only).unwrap(),
            Authenticated::As(Identity::new("dev-admin", vec![GROUP_ADMINS.into()]))
        );

        // A certificate from somewhere else, plus a token that would work:
        // the hard no stands.
        let (_, foreign_leaf) = ca_and_leaf("mallory", None, 90);
        let forged = AuthRequest {
            peer_certs: vec![foreign_leaf],
            authorization: Some("Bearer devtoken".into()),
        };
        assert!(
            chain.authenticate(&forged).is_err(),
            "a token must not rescue a bad certificate"
        );
    }

    #[test]
    fn a_role_survives_the_round_trip_through_its_group() {
        for role in Role::ALL {
            assert_eq!(Role::from_groups(&[role.group().to_string()]), Some(role));
            assert_eq!(Role::parse(role.as_str()), Some(role));
        }
        assert_eq!(Role::from_groups(&["something:else".into()]), None);
        // Admin wins over member when a certificate somehow carries both.
        assert_eq!(
            Role::from_groups(&[GROUP_MEMBERS.into(), GROUP_ADMINS.into()]),
            Some(Role::Admin)
        );
    }
}

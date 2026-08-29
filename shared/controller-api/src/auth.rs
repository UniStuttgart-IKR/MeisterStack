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
use crate::resources::{CertificateSigningRequest, FloatingIp, Image, Vm, Volume};

/// Groups whose name starts with this are the stack's own machinery — nodes,
/// controllers — rather than people. Kubernetes' convention, and its meaning:
/// a system identity is trusted with the tier it belongs to.
pub const SYSTEM_PREFIX: &str = "system:";
/// The group a node's certificate carries; its CN is `system:node:<node_id>`.
pub const GROUP_NODES: &str = "system:nodes";
/// The same one tier up: CN `system:cluster:<cluster_name>`.
pub const GROUP_CLUSTERS: &str = "system:clusters";
/// The two groups a user certificate can carry, one each.
pub const GROUP_ADMINS: &str = "meister:admins";
pub const GROUP_MEMBERS: &str = "meister:members";
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
/// certificate it issues so that a tier without the directory (the cluster)
/// can still tell an admin from a member.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Admin,
    #[default]
    Member,
}

impl Role {
    pub const ALL: [Role; 2] = [Role::Admin, Role::Member];

    /// The group a certificate carries for this role.
    pub fn group(self) -> &'static str {
        match self {
            Role::Admin => GROUP_ADMINS,
            Role::Member => GROUP_MEMBERS,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::Member => "member",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.as_str() == s)
    }

    /// The role a set of groups implies, if any. Admin wins: a certificate
    /// carrying both is not a puzzle worth solving in the negative direction.
    pub fn from_groups(groups: &[String]) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|r| groups.iter().any(|g| g == r.group()))
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

    /// The role this identity's certificate claims. What the cloud does with
    /// it depends on whether it has the directory to check it against — see
    /// `permits`.
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
    pub fn new(links: Vec<Box<dyn Authenticator>>) -> Self {
        Self { links }
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
pub fn classify<'a>(method: &str, path: &'a str) -> Option<Attempt<'a>> {
    let rest = path.strip_prefix("/apis/meister.io/v1/")?;
    let rest = rest.split('?').next().unwrap_or(rest);
    let mut parts = rest.split('/').filter(|s| !s.is_empty());
    let resource = parts.next()?;
    let _name = parts.next();
    let subresource = parts.next();
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
const TENANT_SCOPED: [&str; 4] = [
    Vm::RESOURCE,
    Image::RESOURCE,
    FloatingIp::RESOURCE,
    Volume::RESOURCE,
];

/// Whether a resource is one whose objects belong to a tenant.
pub fn is_tenant_scoped(resource: &str) -> bool {
    TENANT_SCOPED.contains(&resource)
}

/// The verb half of the policy: may this caller do this KIND of thing at all.
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
pub fn permits(
    identity: &Identity,
    role: Option<Role>,
    tenant: Option<&str>,
    attempt: &Attempt<'_>,
) -> bool {
    // Nodes and controllers run the stack; they are not people and there is
    // no object in the directory for them.
    if identity.is_system() {
        return true;
    }
    match (role, attempt.verb) {
        (Some(Role::Admin), _) => true,
        (_, Verb::Approve) => false,
        (Some(Role::Member), Verb::Read) => true,
        // Asking for a certificate is not a privilege — the gate is the
        // approval, which is an admin's. K8s says the same thing: anyone
        // authenticated may create a CSR, approving one is a separate right.
        // Still only for somebody the directory knows: this is the renewal
        // path, not a way in.
        (Some(_), Verb::Write) if attempt.resource == CertificateSigningRequest::RESOURCE => true,
        // A member with a tenant may write its own VMs and images. WHICH
        // objects those are is `permits_object`, run by the handler against
        // the object it is about to touch — this only says the door exists.
        (Some(Role::Member), Verb::Write) => {
            tenant.is_some_and(|t| !t.is_empty()) && is_tenant_scoped(attempt.resource)
        }
        _ => false,
    }
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
    if role != Some(Role::Member) {
        return false;
    }
    let Some(mine) = caller_tenant.filter(|t| !t.is_empty()) else {
        return false;
    };
    let own = scope.tenant == Some(mine);
    match verb {
        // A public image is somebody else's object that everybody may boot
        // from; it is not somebody else's object that everybody may edit.
        Verb::Read => own || scope.public,
        Verb::Write => own,
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
        assert!(permits(&m, Some(Role::Member), t, &read("vms")));
        assert!(permits(&m, Some(Role::Member), t, &write("vms")));
        assert!(permits(&m, Some(Role::Member), t, &write(Image::RESOURCE)));
        assert!(permits(
            &m,
            Some(Role::Member),
            t,
            &write(CertificateSigningRequest::RESOURCE)
        ));
        // Everything else is still an admin's: a member may look at the user
        // directory and at the clusters, and may not write either.
        assert!(!permits(&m, Some(Role::Member), t, &write(User::RESOURCE)));
        assert!(!permits(
            &m,
            Some(Role::Member),
            t,
            &write(Tenant::RESOURCE)
        ));
        assert!(!permits(
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
        assert!(permits(
            &m,
            Some(Role::Member),
            t,
            &write(FloatingIp::RESOURCE)
        ));
        assert!(permits(
            &m,
            Some(Role::Member),
            t,
            &read(FloatingPool::RESOURCE)
        ));
        assert!(permits(
            &m,
            Some(Role::Member),
            t,
            &read(RoutedSubnet::RESOURCE)
        ));
        assert!(!permits(
            &m,
            Some(Role::Member),
            t,
            &write(FloatingPool::RESOURCE)
        ));
        assert!(!permits(
            &m,
            Some(Role::Member),
            t,
            &write(RoutedSubnet::RESOURCE)
        ));

        let admin = Identity::new("root", vec![GROUP_ADMINS.into()]);
        assert!(permits(
            &admin,
            Some(Role::Admin),
            None,
            &write(FloatingPool::RESOURCE)
        ));
        assert!(permits(
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
        assert!(permits(&m, Some(Role::Member), None, &read("vms")));
        assert!(!permits(&m, Some(Role::Member), None, &write("vms")));
        assert!(!permits(&m, Some(Role::Member), Some(""), &write("vms")));
        // The renewal path is not tenant-scoped and stays open.
        assert!(permits(
            &m,
            Some(Role::Member),
            None,
            &write(CertificateSigningRequest::RESOURCE)
        ));
    }

    #[test]
    fn an_admin_may_do_everything_and_a_stranger_nothing() {
        let admin = Identity::new("root", vec![GROUP_ADMINS.into()]);
        assert!(permits(&admin, Some(Role::Admin), None, &write("vms")));
        assert!(permits(
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
        assert!(!permits(&stranger, None, None, &read("vms")));
        assert!(!permits(
            &stranger,
            None,
            None,
            &write(CertificateSigningRequest::RESOURCE)
        ));
    }

    /// Nodes and controllers run the stack and answer to no User object.
    #[test]
    fn a_system_identity_needs_no_directory_entry() {
        let node = Identity::new("system:node:manacor", vec![GROUP_NODES.into()]);
        assert!(node.is_system());
        assert!(permits(&node, None, None, &write("vms")));
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

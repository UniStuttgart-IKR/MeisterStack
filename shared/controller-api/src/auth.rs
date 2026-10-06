// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Authentication chains and REST authorization policy.
//!
//! An authenticator returns `Ok(None)` to defer, an identity to accept, or an
//! error to reject the request without consulting later authenticators. An empty
//! chain is anonymous access, which exists only where `[auth] anonymous = true`
//! asks for it. Identities name callers; roles, resource classes and tenant scope
//! determine their permissions.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

use chrono::{DateTime, TimeDelta, Utc};
use pki::CertInfo;
use rustls_pki_types::CertificateDer;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

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
/// Cloud identity group, with CN `system:cloud:<cloud_name>`.
/// Replicas share this identity for authorized sibling requests.
pub const GROUP_CLOUDS: &str = "system:clouds";
/// The four groups a user certificate can carry, one each.
pub const GROUP_ADMINS: &str = "meister:admins";
pub const GROUP_OPERATORS: &str = "meister:operators";
pub const GROUP_MEMBERS: &str = "meister:members";
pub const GROUP_VIEWERS: &str = "meister:viewers";
/// Privileged group for bootstrap and break-glass credentials. The static
/// bearer identity also uses this group.
pub const GROUP_MASTERS: &str = "system:masters";

/// Directory-backed role. Certificate role groups describe the issued
/// credential; cloud authorization reads the current User grant. Cluster
/// controllers reject ordinary user identities without a directory.
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

    /// Explicit Viewer < Member < Operator < Admin ordering for permission checks.
    /// Enum reordering must not silently change policy.
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
    /// Certificate serial in lowercase colon-separated hex for revocation lookup.
    /// None for other credential types; one user may hold several certificates.
    pub serial: Option<String>,
    // --- end lane 5A ---------------------------------------------------
}

impl Identity {
    pub fn new(name: impl Into<String>, groups: Vec<String>) -> Self {
        Self {
            name: name.into(),
            groups,
            serial: None,
        }
    }

    // --- lane 5A ---
    /// The same identity, with the certificate it came out of named.
    pub fn with_serial(mut self, serial: impl Into<String>) -> Self {
        self.serial = Some(serial.into());
        self
    }
    // --- end lane 5A ---

    pub fn has_group(&self, group: &str) -> bool {
        self.groups.iter().any(|g| g == group)
    }

    /// A node, a controller, or anything else the stack runs itself.
    pub fn is_system(&self) -> bool {
        self.name.starts_with(SYSTEM_PREFIX)
            || self.groups.iter().any(|g| g.starts_with(SYSTEM_PREFIX))
    }

    /// Read the certificate's descriptive role label.
    /// Authorization uses the directory role instead; see `rest::grant_of`.
    pub fn claimed_role(&self) -> Option<Role> {
        Role::from_groups(&self.groups)
    }

    /// The certificate name a peer of `kind` ("node", "cluster") called
    /// `peer` gets from the generator.
    pub fn peer_name(kind: &str, peer: &str) -> String {
        format!("{SYSTEM_PREFIX}{kind}:{peer}")
    }

    /// Check a Hello against its certificate identity. A named machine
    /// identity must match both peer kind and name. A group-only credential
    /// without a named system peer retains shared-identity behavior.
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

/// Transport-independent authentication inputs, shared by REST and gRPC.
/// Owned certificate and token data also permit tests without a live handshake.
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

    /// Whether this authenticator currently has the material needed to
    /// verify credentials. Local credentials are ready on construction;
    /// remotely fetched keys may leave a configured authenticator degraded.
    fn ready(&self) -> bool {
        true
    }
}

/// What the chain concluded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Authenticated {
    /// No authenticator is configured: every request is anonymous and may
    /// do anything. A controller builds this only when `[auth] anonymous =
    /// true` asks for it; it is never a default.
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
    /// Ordered authenticator names for discovery, excluding credential material
    /// and local configuration paths.
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

    /// Current discovery description: comma-separated authenticators, with
    /// `:degraded` for configured but unready links. An empty chain is `none`
    /// (anonymous mode). Compute on demand so readiness changes remain visible.
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

// Reloadable application-level revocation shared by REST and session auth.
// Handshake configuration alone cannot update established sessions or reload
// new revocations without rebuilding the server.

/// How often the file is looked at again. Not how often it is READ: the
/// mtime is looked at, and the file is read when the mtime moved.
pub const REVOCATION_RELOAD_SECS: i64 = 30;

/// What the list said, when it was read, and what it was read from.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RevocationList {
    /// Normalised serials — lowercase hex, no separators, no leading zero
    /// bytes. See [`normalise_serial`].
    pub serials: BTreeSet<String>,
    pub crl_number: Option<u64>,
    pub loaded_at: Option<DateTime<Utc>>,
    pub path: PathBuf,
    /// The modification time this list was read at. `None` when the file
    /// system would not say — and then every check re-reads, which is the
    /// safe direction.
    pub mtime: Option<std::time::SystemTime>,
    /// File length supplements mtime when detecting changes within one filesystem
    /// timestamp tick. Same-size replacements still require a changed mtime.
    pub size: Option<u64>,
}

impl RevocationList {
    pub fn is_revoked(&self, serial: &str) -> bool {
        self.serials.contains(&normalise_serial(serial))
    }

    pub fn len(&self) -> usize {
        self.serials.len()
    }

    pub fn is_empty(&self) -> bool {
        self.serials.is_empty()
    }
}

/// Normalize certificate serials across colon-separated X.509 text and
/// OpenSSL uppercase hex, removing DER sign padding before comparison.
pub fn normalise_serial(serial: &str) -> String {
    // Use the shared PKI normalization so issuance and authentication compare
    // certificate serials identically.
    pki::tls::normalise_serial(serial)
}

/// What one look at the file came to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reload {
    /// Less than [`REVOCATION_RELOAD_SECS`] since the last look.
    TooSoon,
    /// The file has not moved.
    Unchanged,
    /// It moved and it was read: this many serials, this crl number.
    Loaded {
        serials: usize,
        crl_number: Option<u64>,
    },
    /// Reload failed, rolled back its CRL number, or reused a number with changed
    /// content. The previously accepted list remains enforced.
    Failed(String),
}

/// Shared revocation state for new authentication and established sessions.
/// Both paths must use the same accepted list.
#[derive(Debug)]
pub struct Revocations {
    path: PathBuf,
    list: RwLock<RevocationList>,
    /// When the mtime was last looked at. Its own lock so that a check
    /// never waits on a reader of the list.
    checked: Mutex<Option<DateTime<Utc>>>,
}

impl Revocations {
    /// Load the configured CRL or fail startup. Continuing with an empty list
    /// would silently permit credentials the deployment intended to revoke.
    pub fn load(path: &Path) -> anyhow::Result<Arc<Revocations>> {
        Self::load_at(path, Utc::now())
    }

    pub fn load_at(path: &Path, now: DateTime<Utc>) -> anyhow::Result<Arc<Revocations>> {
        let list = Self::read(path, now)?;
        info!(
            crl = %path.display(),
            revoked = list.serials.len(),
            number = list.crl_number.unwrap_or_default(),
            "revocation list loaded"
        );
        Ok(Arc::new(Revocations {
            path: path.to_path_buf(),
            list: RwLock::new(list),
            checked: Mutex::new(Some(now)),
        }))
    }

    fn read(path: &Path, now: DateTime<Utc>) -> anyhow::Result<RevocationList> {
        let crl = pki::tls::read_crl(path)?;
        let (mtime, size) = Self::stamp(path);
        Ok(RevocationList {
            serials: crl.serials.iter().map(|s| normalise_serial(s)).collect(),
            crl_number: crl.number,
            loaded_at: Some(now),
            path: path.to_path_buf(),
            mtime,
            size,
        })
    }

    fn stamp(path: &Path) -> (Option<std::time::SystemTime>, Option<u64>) {
        match std::fs::metadata(path) {
            Ok(meta) => (meta.modified().ok(), Some(meta.len())),
            Err(_) => (None, None),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Validate a CRL without retaining it and report its serial count and number.
    pub fn check(path: &Path) -> anyhow::Result<String> {
        let list = Self::read(path, Utc::now())?;
        Ok(format!(
            "{}: {} revoked serial(s), crl number {}",
            path.display(),
            list.serials.len(),
            list.crl_number
                .map(|n| n.to_string())
                .unwrap_or_else(|| "none".to_string())
        ))
    }

    /// A copy of what is currently enforced.
    pub fn list(&self) -> RevocationList {
        self.list.read().expect("revocation list").clone()
    }

    /// Is this serial on the list? The crl number comes back with the
    /// answer, because a refusal that cannot say which list it came from is
    /// a refusal nobody can check.
    pub fn revoked(&self, serial: &str) -> Option<Option<u64>> {
        let list = self.list.read().expect("revocation list");
        list.is_revoked(serial).then_some(list.crl_number)
    }

    /// Check file metadata at most every `REVOCATION_RELOAD_SECS` and reload changes.
    /// Failed reloads retain the accepted list and report the failure.
    pub fn refresh(&self) -> Reload {
        self.refresh_at(Utc::now())
    }

    pub fn refresh_at(&self, now: DateTime<Utc>) -> Reload {
        {
            let mut checked = self.checked.lock().expect("revocation clock");
            if let Some(last) = *checked
                && now.signed_duration_since(last) < TimeDelta::seconds(REVOCATION_RELOAD_SECS)
            {
                return Reload::TooSoon;
            }
            *checked = Some(now);
        }
        let seen = Self::stamp(&self.path);
        let held = {
            let list = self.list.read().expect("revocation list");
            (list.mtime, list.size)
        };
        // `None` on either side means the file system would not say, and
        // then the file is read rather than believed unchanged.
        if seen.0.is_some() && held.0.is_some() && seen == held {
            return Reload::Unchanged;
        }
        match Self::read(&self.path, now) {
            Ok(fresh) => {
                let (held_number, held_serials) = {
                    let list = self.list.read().expect("revocation list");
                    (list.crl_number, list.serials.clone())
                };
                // Keep the accepted CRL on rollback or same-number content changes.
                // This application-level reload supplements the startup TLS CRL.
                if let (Some(held_n), Some(fresh_n)) = (held_number, fresh.crl_number)
                    && fresh_n < held_n
                {
                    let why = format!(
                        "{} carries crl number {fresh_n}, older than the {held_n} already \
                         enforced; a revocation list that goes backwards is refused",
                        self.path.display()
                    );
                    warn!(
                        crl = %self.path.display(),
                        error = %why,
                        "an older revocation list was offered; the one this process already \
                         holds stays in force"
                    );
                    return Reload::Failed(why);
                }
                if held_number.is_some()
                    && held_number == fresh.crl_number
                    && held_serials != fresh.serials
                {
                    let why = format!(
                        "{} carries crl number {}, the same as the list already enforced, but \
                         different content; a crl number is refused as a distinguisher once it \
                         repeats",
                        self.path.display(),
                        held_number.expect("checked above")
                    );
                    warn!(
                        crl = %self.path.display(),
                        error = %why,
                        "a revocation list with a repeated crl number and different content \
                         was offered; the one this process already holds stays in force"
                    );
                    return Reload::Failed(why);
                }
                let answer = Reload::Loaded {
                    serials: fresh.serials.len(),
                    crl_number: fresh.crl_number,
                };
                *self.list.write().expect("revocation list") = fresh;
                answer
            }
            Err(e) => {
                let why = format!("{e:#}");
                warn!(
                    crl = %self.path.display(),
                    error = %why,
                    "the revocation list could not be read; the one this process already \
                     holds stays in force"
                );
                Reload::Failed(why)
            }
        }
    }
}
// --- end lane 5A -----------------------------------------------------------

/// Verify a client certificate and extract its CN as name and O fields as groups.
/// This repeats transport verification and also supports direct, socket-free use.
pub struct MtlsAuthenticator {
    cas: Vec<CertificateDer<'static>>,
    /// Optional reloadable revocations, shared with active-session registries.
    revocations: Option<Arc<Revocations>>,
    // --- end lane 5A ---
}

impl MtlsAuthenticator {
    pub fn new(cas: Vec<CertificateDer<'static>>) -> Self {
        Self {
            cas,
            revocations: None,
        }
    }

    // --- lane 5A ---
    pub fn with_revocations(mut self, revocations: Option<Arc<Revocations>>) -> Self {
        self.revocations = revocations;
        self
    }
    // --- end lane 5A ---

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
        // Verify the chain and validity before consulting serial revocations.
        // A serial has meaning only within its issuing CA.
        if let Some(revocations) = &self.revocations {
            revocations.refresh_at(now);
            if let Some(number) = revocations.revoked(&info.serial) {
                anyhow::bail!(
                    "certificate {} for {:?} is revoked (CRL {})",
                    info.serial,
                    info.common_name,
                    number
                        .map(|n| n.to_string())
                        .unwrap_or_else(|| "unnumbered".to_string())
                );
            }
        }
        // --- end lane 5A -------------------------------------------------
        Ok(Some(identity_of(&info)))
    }
}

/// The mapping, in one place because two tiers and the generator all have to
/// mean the same thing by it.
pub fn identity_of(info: &CertInfo) -> Identity {
    Identity {
        name: info.common_name.clone(),
        groups: info.organizations.clone(),
        // --- lane 5A ---
        serial: Some(info.serial.clone()),
        // --- end lane 5A ---
    }
}

impl Authenticator for MtlsAuthenticator {
    fn authenticate(&self, req: &AuthRequest) -> anyhow::Result<Option<Identity>> {
        self.authenticate_at(req, Utc::now())
    }
}

/// Static bearer credential for development and bootstrap access.
/// It has one identity and no built-in expiry, rotation or per-user isolation.
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

/// Classify API object routes for authorization. Health/readiness,
/// discovery and schemas return None and are publicly readable.
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
    // Do not classify unauthenticated CORS preflight as a write. This does not
    // grant access or provide an OPTIONS handler.
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

/// Resources members may write within their own tenant. Infrastructure
/// provisioning remains separate; address and volume creation still enforce
/// pool quotas in their handlers.
const TENANT_SCOPED: [&str; 8] = [
    Vm::RESOURCE,
    Image::RESOURCE,
    FloatingIp::RESOURCE,
    Volume::RESOURCE,
    // A snapshot is a copy of a tenant's data and is therefore the tenant's,
    // by exactly the argument the volume it came from is.
    crate::resources::VolumeSnapshot::RESOURCE,
    // Secrets are tenant-owned. Read handlers return redacted key names rather
    // than plaintext values; see `Secret::redacted`.
    crate::resources::Secret::RESOURCE,
    // A migration is a record of what happened to a tenant's VM, so it is
    // filed in that tenant and read by them. It is the one resource here
    // whose WRITE door is not the tenant's — see `Class::TenantOperated`.
    crate::resources::VmMigration::RESOURCE,
    // Router reads are tenant-scoped; writes require infrastructure privileges
    // because routers consume provider networks and gateway capacity.
    crate::resources::Router::RESOURCE,
];

/// Whether a resource is one whose objects belong to a tenant.
pub fn is_tenant_scoped(resource: &str) -> bool {
    TENANT_SCOPED.contains(&resource)
}

/// Resource policy classes used by the role table.
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
    /// Tenant-scoped reads with operator-only writes, used for migrations
    /// and routers that consume fleet or gateway capacity.
    TenantOperated,
}

/// Classify CSR approval as directory administration; other CSR operations
/// use CsrCreate. Only the approval subresource produces `Verb::Approve`.
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
        // Remaining resources use infrastructure policy. Event handlers additionally
        // filter inventory for tenant-confined callers.
        _ => Class::Infra,
    }
}

/// Minimum role for a resource class and verb.
/// None denotes an unsupported combination, bypassed only by masters policy.
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

/// Check resource-class and verb permissions for an established grant.
///
/// `role` and `tenant` come from the cloud User directory. Middleware refuses
/// ordinary users at tiers without that directory; certificate role claims
/// are not a fallback. Tenant object checks follow in `permits_object`.
///
/// The masters group bypasses this policy. Other machine identities may only
/// read as an exact sibling identity, or make the explicitly allowed forwarded
/// writes. Both peer kind and peer name must match.
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
        // Machine identities need an exact sibling match at REST. Including kind
        // prevents equally named cloud and cluster identities from crossing tiers.
        return match (own_peer, attempt.verb) {
            (Some(peer), Verb::Read) => identity.name == Identity::peer_name(peer.kind, peer.name),
            // Forwarded writes are limited to `forwardable_write` routes.
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
    // Member writes to tenant resources require an established tenant.
    // Object-level policy checks the actual owner separately.
    if class == Class::Tenant && attempt.verb == Verb::Write && role < Role::Operator {
        return tenant.is_some_and(|t| !t.is_empty());
    }
    true
}

/// Writes that require a session held by another replica: cluster node
/// updates, node migration commands and cloud migration creation. This route
/// allowlist supplements exact sibling identity and forwarding-marker checks.
fn forwardable_write(attempt: &Attempt<'_>) -> bool {
    let cluster_node = attempt.resource == crate::resources::Cluster::RESOURCE
        && attempt.subresource == Some("nodes");
    let node_command = attempt.resource == crate::resources::Node::RESOURCE
        && attempt.subresource == Some("commands");
    let vm_migration = attempt.resource == crate::resources::VmMigration::RESOURCE
        && attempt.subresource.is_none();
    cluster_node || node_command || vm_migration
}

/// This tier's sibling identity for REST reads and selected forwarded writes.
/// Kind and name must both match; equal names across tiers confer no access.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnPeer<'a> {
    /// `"cluster"` or `"cloud"` — the middle word of the certificate's CN.
    pub kind: &'a str,
    /// This tier's own name: the cluster name, or the cloud name.
    pub name: &'a str,
    /// Whether `x-meister-forwarded` is present. Selected writes require this
    /// marker and the exact sibling identity. The marker alone authenticates
    /// nothing; see `forwardable_write` for the route allowlist.
    pub forwarded: bool,
}

/// Object ownership and public-read scope. Defaults provide neither tenant
/// ownership nor public access, so members cannot access unscoped legacy objects.
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

/// Check object scope after resource/verb authorization.
/// Handlers must call this after loading ownership, and listings must filter
/// equivalently to avoid exposing unauthorized inventory.
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
    // Remaining tenant-scoped operations require a directory role and tenant;
    // verb permissions have already been checked separately.
    let Some(role) = role else {
        return false;
    };
    let Some(mine) = caller_tenant.filter(|t| !t.is_empty()) else {
        return false;
    };
    let own = scope.tenant == Some(mine);
    match verb {
        // Operators may read across tenants; public images are also readable.
        // Neither exception grants cross-tenant writes.
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

    /// Members may reserve floating addresses but cannot create pools or subnets.
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

    /// Assert each permission-table cell from independent expected policy values.
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

        // TenantOperated permits tenant reads but requires operator privileges to write.
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

    /// Machine identities without an authorized sibling context have no REST access,
    /// except through the masters override.
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

    /// Forwarded node writes require both the exact sibling credential and
    /// the forwarding marker; other writes remain refused.
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

        // Cloud migration requests may forward to the sibling holding the cluster
        // session, using the same restricted-write mechanism as node patches.
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

    /// A cluster sibling may forward migration commands only with its exact identity,
    /// the forwarded marker and the permitted route.
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

    /// Route classification must produce the resource and verb the forwarding
    /// authorization rule expects.
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

    /// Public images permit cross-tenant reads while retaining owner-only writes.
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

    /// Operators read across tenants but write only within their own tenant.
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

    /// Peer authorization includes kind as well as name, preventing a node
    /// certificate from impersonating a cluster signed by the same CA.
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

    // --- lane 5A: revocation ------------------------------------------

    /// Generate a CA, two chosen leaf serials and a signed CRL for revocation tests.
    fn ca_leaves_and_crl(
        revoke: &[u64],
        crl_number: u64,
    ) -> (Vec<CertificateDer<'static>>, Vec<Vec<u8>>, String) {
        use rcgen::{
            BasicConstraints, CertificateParams, CertificateRevocationListParams, DnType, IsCa,
            Issuer, KeyPair, KeyUsagePurpose, RevocationReason, RevokedCertParams, SerialNumber,
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

        let epoch = Utc::now().timestamp();
        let mut leaves = Vec::new();
        for (index, cn) in ["alice", "bob"].iter().enumerate() {
            let key = KeyPair::generate().unwrap();
            let mut params = CertificateParams::new(Vec::new()).unwrap();
            params.distinguished_name.push(DnType::CommonName, *cn);
            params
                .distinguished_name
                .push(DnType::OrganizationName, GROUP_MEMBERS);
            params.serial_number = Some(SerialNumber::from(index as u64 + 1));
            params.not_before = time::OffsetDateTime::from_unix_timestamp(epoch - 60).unwrap();
            params.not_after =
                time::OffsetDateTime::from_unix_timestamp(epoch + 90 * 86_400).unwrap();
            leaves.push(params.signed_by(&key, &issuer).unwrap().der().to_vec());
        }

        let now = time::OffsetDateTime::from_unix_timestamp(epoch).unwrap();
        let crl = CertificateRevocationListParams {
            this_update: now,
            next_update: now + time::Duration::days(30),
            crl_number: SerialNumber::from(crl_number),
            issuing_distribution_point: None,
            revoked_certs: revoke
                .iter()
                .map(|serial| RevokedCertParams {
                    serial_number: SerialNumber::from(*serial),
                    revocation_time: now,
                    reason_code: Some(RevocationReason::KeyCompromise),
                    invalidity_date: None,
                })
                .collect(),
            key_identifier_method: rcgen::KeyIdMethod::Sha256,
        }
        .signed_by(&issuer)
        .unwrap();

        (vec![ca_cert.der().clone()], leaves, crl.pem().unwrap())
    }

    fn crl_file(dir: &tempfile::TempDir, pem: &str) -> std::path::PathBuf {
        let path = dir.path().join("crl.pem");
        std::fs::write(&path, pem).unwrap();
        path
    }

    /// The three spellings of one number in this stack, and the one this
    /// process compares in.
    #[test]
    fn a_serial_has_one_spelling_here() {
        // x509-parser's (a certificate, a crl entry) and openssl's (an
        // index, a receipt, what an operator retypes).
        assert_eq!(normalise_serial("64:35:C9:c4"), "6435c9c4");
        assert_eq!(normalise_serial("6435c9c4"), "6435c9c4");
        // DER's sign padding says nothing about the number.
        assert_eq!(normalise_serial("00:64:35"), "6435");
        assert_eq!(normalise_serial("0x6435"), "6435");
        // and a number somebody wrote without its leading zero
        assert_eq!(normalise_serial("5"), "05");
        // zero stays a number rather than becoming the empty string
        assert_eq!(normalise_serial("00"), "00");
    }

    /// The whole of D11 in one assertion: the certificate is still valid,
    /// still signed by this CA, still in date — and it is refused, with the
    /// number of the list that refused it.
    #[test]
    fn a_revoked_certificate_is_refused_where_both_ports_pass() {
        let dir = tempfile::tempdir().unwrap();
        let (cas, leaves, pem) = ca_leaves_and_crl(&[1], 7);
        let path = crl_file(&dir, &pem);
        let auth = MtlsAuthenticator::new(cas).with_revocations(Some(
            Revocations::load(&path).expect("a list this test just wrote"),
        ));

        let refused = auth
            .authenticate_at(
                &AuthRequest::with_certs(vec![leaves[0].clone()]),
                Utc::now(),
            )
            .unwrap_err()
            .to_string();
        assert!(refused.contains("is revoked"), "{refused}");
        assert!(refused.contains("alice"), "{refused}");
        assert!(refused.contains("CRL 7"), "{refused}");

        // And the one nobody revoked is untouched.
        let who = auth
            .authenticate_at(
                &AuthRequest::with_certs(vec![leaves[1].clone()]),
                Utc::now(),
            )
            .unwrap()
            .expect("recognised");
        assert_eq!(who.name, "bob");
        assert_eq!(who.serial.as_deref(), Some("02"));
    }

    /// An identity that came out of a certificate says which certificate.
    /// It is what a session registry has to hold to be able to drop itself.
    #[test]
    fn an_identity_out_of_a_certificate_carries_its_serial() {
        let (cas, leaves, _) = ca_leaves_and_crl(&[], 1);
        let who = MtlsAuthenticator::new(cas)
            .authenticate_at(
                &AuthRequest::with_certs(vec![leaves[0].clone()]),
                Utc::now(),
            )
            .unwrap()
            .unwrap();
        assert_eq!(who.serial.as_deref(), Some("01"));
        // A token is not a certificate and has no serial to carry.
        let token = BearerAuthenticator::new("t", Identity::new("dev", vec![]))
            .authenticate(&AuthRequest {
                peer_certs: Vec::new(),
                authorization: Some("Bearer t".into()),
            })
            .unwrap()
            .unwrap();
        assert_eq!(token.serial, None);
    }

    /// An empty list is a list. Nothing is revoked, and every certificate
    /// goes through — which is the state a fleet is in the day it starts
    /// publishing one.
    #[test]
    fn an_empty_list_revokes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let (cas, leaves, pem) = ca_leaves_and_crl(&[], 1);
        let path = crl_file(&dir, &pem);
        let auth =
            MtlsAuthenticator::new(cas).with_revocations(Some(Revocations::load(&path).unwrap()));
        for leaf in leaves {
            assert!(
                auth.authenticate_at(&AuthRequest::with_certs(vec![leaf]), Utc::now())
                    .unwrap()
                    .is_some()
            );
        }
    }

    /// "Nothing is revoked" and "the list could not be read" are the two
    /// answers that must never be confused, because one of them is the one
    /// an attacker wants. So a file that is not a list is a start-up error.
    #[test]
    fn a_list_that_cannot_be_read_is_not_an_empty_list() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nowhere.pem");
        assert!(Revocations::load(&missing).is_err());

        let junk = dir.path().join("junk.pem");
        std::fs::write(&junk, b"this is not a crl\n").unwrap();
        let err = Revocations::load(&junk).unwrap_err().to_string();
        assert!(err.contains("revocation list"), "{err}");
    }

    /// The point of the whole design: a certificate stops working without
    /// anything being restarted.
    #[test]
    fn a_new_list_takes_effect_without_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let (cas, leaves, empty) = ca_leaves_and_crl(&[], 1);
        let path = crl_file(&dir, &empty);
        let revocations = Revocations::load(&path).unwrap();
        let auth = MtlsAuthenticator::new(cas).with_revocations(Some(revocations.clone()));
        let bob = AuthRequest::with_certs(vec![leaves[1].clone()]);
        let now = Utc::now();
        assert!(auth.authenticate_at(&bob, now).unwrap().is_some());

        // The same CA, a new list. This is what `apply` delivers: one file,
        // written where the old one was.
        let (_, _, with_bob) = ca_leaves_and_crl(&[2], 8);
        std::fs::write(&path, with_bob).unwrap();

        // Within the half minute nothing is even looked at…
        assert_eq!(revocations.refresh_at(now), Reload::TooSoon);
        // …and after it, the new list is in force without anything having
        // been restarted.
        let later = now + TimeDelta::seconds(REVOCATION_RELOAD_SECS + 1);
        let refused = auth.authenticate_at(&bob, later).unwrap_err().to_string();
        assert!(refused.contains("is revoked"), "{refused}");
        assert_eq!(revocations.list().crl_number, Some(8));

        // A second look at a file that has not moved reads nothing.
        assert_eq!(
            revocations.refresh_at(later + TimeDelta::seconds(REVOCATION_RELOAD_SECS + 1)),
            Reload::Unchanged
        );
    }

    /// And the failure direction of the same thing: a list that becomes
    /// unreadable does not become an empty one.
    #[test]
    fn a_list_that_becomes_unreadable_keeps_the_one_in_force() {
        let dir = tempfile::tempdir().unwrap();
        let (cas, leaves, pem) = ca_leaves_and_crl(&[1], 3);
        let path = crl_file(&dir, &pem);
        let revocations = Revocations::load(&path).unwrap();
        let auth = MtlsAuthenticator::new(cas).with_revocations(Some(revocations.clone()));
        let alice = AuthRequest::with_certs(vec![leaves[0].clone()]);
        let now = Utc::now();
        assert!(auth.authenticate_at(&alice, now).is_err());

        std::fs::write(&path, b"half a file").unwrap();
        let later = now + TimeDelta::seconds(REVOCATION_RELOAD_SECS + 1);
        assert!(matches!(revocations.refresh_at(later), Reload::Failed(_)));
        // Still refused, and still by list 3.
        let refused = auth.authenticate_at(&alice, later).unwrap_err().to_string();
        assert!(refused.contains("CRL 3"), "{refused}");
        assert_eq!(revocations.list().crl_number, Some(3));
    }

    /// Reject CRL rollback so replacing a file cannot undo accepted revocations.
    #[test]
    fn restoring_an_older_crl_does_not_forget_a_later_revocation() {
        let dir = tempfile::tempdir().unwrap();
        let (cas, leaves, empty) = ca_leaves_and_crl(&[], 1);
        let path = crl_file(&dir, &empty);
        let revocations = Revocations::load(&path).unwrap();
        let auth = MtlsAuthenticator::new(cas).with_revocations(Some(revocations.clone()));
        let bob = AuthRequest::with_certs(vec![leaves[1].clone()]);
        let now = Utc::now();
        assert!(auth.authenticate_at(&bob, now).unwrap().is_some());

        let (_, _, with_bob) = ca_leaves_and_crl(&[2], 8);
        std::fs::write(&path, with_bob).unwrap();
        let later = now + TimeDelta::seconds(REVOCATION_RELOAD_SECS + 1);
        assert!(matches!(
            revocations.refresh_at(later),
            Reload::Loaded { .. }
        ));
        assert!(auth.authenticate_at(&bob, later).is_err());
        assert_eq!(revocations.list().crl_number, Some(8));

        // The original list, written back where the new one was: same
        // path, an older number, bob not on it.
        let (_, _, original) = ca_leaves_and_crl(&[], 1);
        std::fs::write(&path, original).unwrap();
        let even_later = later + TimeDelta::seconds(REVOCATION_RELOAD_SECS + 1);
        assert!(matches!(
            revocations.refresh_at(even_later),
            Reload::Failed(_)
        ));
        // Bob is still refused, and the list this process enforces is
        // still number 8.
        let refused = auth
            .authenticate_at(&bob, even_later)
            .unwrap_err()
            .to_string();
        assert!(refused.contains("is revoked"), "{refused}");
        assert_eq!(revocations.list().crl_number, Some(8));
    }

    /// Reject changed CRL content that reuses an already accepted number.
    #[test]
    fn a_repeated_crl_number_with_different_content_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (cas, leaves, with_bob) = ca_leaves_and_crl(&[2], 8);
        let path = crl_file(&dir, &with_bob);
        let revocations = Revocations::load(&path).unwrap();
        let auth = MtlsAuthenticator::new(cas).with_revocations(Some(revocations.clone()));
        let bob = AuthRequest::with_certs(vec![leaves[1].clone()]);
        let now = Utc::now();
        assert!(auth.authenticate_at(&bob, now).is_err());

        let (_, _, same_number_different_content) = ca_leaves_and_crl(&[], 8);
        std::fs::write(&path, same_number_different_content).unwrap();
        let later = now + TimeDelta::seconds(REVOCATION_RELOAD_SECS + 1);
        assert!(matches!(revocations.refresh_at(later), Reload::Failed(_)));
        assert!(auth.authenticate_at(&bob, later).is_err());
        assert_eq!(revocations.list().crl_number, Some(8));
    }

    /// Reject a foreign issuer before interpreting its serial as a local revocation.
    #[test]
    fn a_foreign_certificate_with_a_revoked_serial_is_refused_as_foreign() {
        let dir = tempfile::tempdir().unwrap();
        let (cas, _, pem) = ca_leaves_and_crl(&[1], 1);
        let path = crl_file(&dir, &pem);
        // Somebody else's CA, and their leaf carries serial 1 as well.
        let (_, theirs, _) = ca_leaves_and_crl(&[], 1);
        let auth =
            MtlsAuthenticator::new(cas).with_revocations(Some(Revocations::load(&path).unwrap()));
        let err = auth
            .authenticate_at(
                &AuthRequest::with_certs(vec![theirs[0].clone()]),
                Utc::now(),
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("no configured CA"), "{err}");
    }

    /// A CRL loaded into rustls rejects revoked clients at the handshake, before
    /// application authentication. Runtime reload is tested separately.
    #[tokio::test]
    async fn rustls_refuses_the_handshake_of_a_revoked_client() {
        use rcgen::{
            BasicConstraints, CertificateParams, CertificateRevocationListParams, DnType, IsCa,
            Issuer, KeyPair, KeyUsagePurpose, RevocationReason, RevokedCertParams, SerialNumber,
        };
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let dir = tempfile::tempdir().unwrap();
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "meister-ca");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let issuer = Issuer::new(ca_params, ca_key);

        let leaf = |cn: &str, sans: Vec<String>, serial: u64| {
            let key = KeyPair::generate().unwrap();
            let mut params = CertificateParams::new(sans).unwrap();
            params.distinguished_name.push(DnType::CommonName, cn);
            params.serial_number = Some(SerialNumber::from(serial));
            let cert = params.signed_by(&key, &issuer).unwrap();
            (cert.pem(), key.serialize_pem())
        };
        let (server_pem, server_key) = leaf("localhost", vec!["localhost".to_string()], 10);
        let (client_pem, client_key) = leaf("system:node:n1", Vec::new(), 11);

        let crl = CertificateRevocationListParams {
            this_update: time::OffsetDateTime::now_utc(),
            next_update: time::OffsetDateTime::now_utc() + time::Duration::days(30),
            crl_number: SerialNumber::from(1u64),
            issuing_distribution_point: None,
            revoked_certs: vec![RevokedCertParams {
                serial_number: SerialNumber::from(11u64),
                revocation_time: time::OffsetDateTime::now_utc(),
                reason_code: Some(RevocationReason::KeyCompromise),
                invalidity_date: None,
            }],
            key_identifier_method: rcgen::KeyIdMethod::Sha256,
        }
        .signed_by(&issuer)
        .unwrap();

        let write = |name: &str, text: &str, mode: u32| {
            use std::os::unix::fs::PermissionsExt;
            let path = dir.path().join(name);
            std::fs::write(&path, text).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            path
        };
        let ca_path = write("ca.crt", &ca_cert.pem(), 0o644);
        let cert_path = write("serving.crt", &server_pem, 0o644);
        let key_path = write("serving.key", &server_key, 0o600);
        let crl_path = write("crl.pem", &crl.pem().unwrap(), 0o644);
        let client_cert = write("client.crt", &client_pem, 0o644);
        let client_key_path = write("client.key", &client_key, 0o600);

        let config =
            pki::tls::server_config(&cert_path, &key_path, Some(&ca_path), Some(&crl_path))
                .expect("a server config with a list in it");
        let acceptor = tokio_rustls::TlsAcceptor::from(config);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            // Two connections: the revoked one and the good one.
            for _ in 0..2 {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    if let Ok(mut tls) = acceptor.accept(stream).await {
                        let _ = tls.write_all(b"hello").await;
                        // A clean close, so that the good case is told
                        // apart from a peer that went away.
                        let _ = tls.shutdown().await;
                    }
                });
            }
        });

        // Read after connecting: TLS 1.3 can deliver the server's client-certificate
        // rejection as an alert on the first read rather than during client connect.
        let dial = |cert: std::path::PathBuf, key: std::path::PathBuf| {
            let ca_path = ca_path.clone();
            async move {
                let client = pki::tls::client_config(Some(&ca_path), Some((&cert, &key))).unwrap();
                let connector = tokio_rustls::TlsConnector::from(client);
                let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
                let name = rustls_pki_types::ServerName::try_from("localhost").unwrap();
                let mut tls = connector.connect(name, tcp).await?;
                let mut said = Vec::new();
                tls.read_to_end(&mut said).await?;
                Ok::<Vec<u8>, std::io::Error>(said)
            }
        };

        let refused = dial(client_cert, client_key_path).await;
        assert!(
            refused.is_err(),
            "rustls let a revoked client certificate through the handshake: {refused:?}"
        );

        // The counter-probe, on the same listener: a certificate from the
        // same CA that is NOT on the list gets in.
        let (ok_pem, ok_key) = leaf("system:node:n2", Vec::new(), 12);
        let ok_cert = write("ok.crt", &ok_pem, 0o644);
        let ok_key_path = write("ok.key", &ok_key, 0o600);
        assert_eq!(
            dial(ok_cert, ok_key_path).await.expect("not revoked"),
            b"hello".to_vec(),
            "a certificate nobody revoked was refused"
        );
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
        // Name and groups, not the whole value: an identity out of a
        // certificate carries the serial of that certificate now (lane 5A),
        // and it is a fresh one every time this test mints a CA.
        let Authenticated::As(who) = chain.authenticate(&with_cert).unwrap() else {
            panic!("the certificate should have been recognised");
        };
        assert_eq!(who.name, "alice");
        assert_eq!(who.groups, vec![GROUP_MEMBERS.to_string()]);
        assert!(who.serial.is_some(), "it came out of a certificate");

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

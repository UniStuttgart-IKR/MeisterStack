// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! `fleet.toml` — the plan, and everything that follows from it.
//!
//! One file describes the boxes and their roles; Nix reads it with
//! `builtins.fromTOML` and this module reads the same bytes with serde. Two
//! readers of one file rather than one reader and one generator: nothing here
//! evaluates Nix, and nothing in `nix/fleet.nix` shells out to this binary, so
//! neither half can be down when the other one runs. What keeps them in step
//! is that the derivations below are the ones `nix/fleet.nix` spells out in
//! the same order, and the tests at the bottom pin them.
//!
//! What is DERIVED and never typed twice: the etcd peer set of a raft group,
//! the cluster name, an agent's `controller_addrs`, a cluster's
//! `cloud_addrs`, and every `advertise_api`. A plan says who is a member of
//! what; addresses follow.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

/// The four ports this stack listens on, in one place because both the plan
/// and `check` name them. REST and session are two listeners per tier, and
/// the numbers are the lab's (`lab/LAB.md`) and the images' defaults.
pub const CLOUD_API_PORT: u16 = 3000;
pub const CLOUD_SESSION_PORT: u16 = 50050;
pub const CLUSTER_API_PORT: u16 = 3001;
pub const CLUSTER_SESSION_PORT: u16 = 50051;

/// Kanidm, Loki and Tempo on an `addons` node — the addresses a node with
/// that role hands the rest of the fleet (see `nix/addons.nix`).
pub const KANIDM_PORT: u16 = 8443;
pub const LOKI_PORT: u16 = 3100;
pub const OTLP_PORT: u16 = 4317;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    // The order of these variants IS the deployment order: the new binary
    // goes to the BOTTOM tier first, so a controller can never issue a
    // command the tier below it does not understand yet (deploy/push.sh says
    // the same thing, and has since M4.6). Addons last because nothing in the
    // control plane waits for them.
    Agent,
    Cluster,
    Cloud,
    Addons,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Cloud => "cloud",
            Role::Cluster => "cluster",
            Role::Agent => "agent",
            Role::Addons => "addons",
        }
    }

    /// The unit `push` restarts and `check` asks after. Addons has no single
    /// unit — it is six of them — so it has no answer here.
    pub fn unit(self) -> Option<&'static str> {
        match self {
            Role::Cloud => Some("meister-cloud-controller"),
            Role::Cluster => Some("meister-cluster-controller"),
            Role::Agent => Some("meister-agent"),
            Role::Addons => None,
        }
    }

    pub fn parse(s: &str) -> Result<Role> {
        Ok(match s {
            "cloud" => Role::Cloud,
            "cluster" => Role::Cluster,
            "agent" => Role::Agent,
            "addons" => Role::Addons,
            // `both` and `all` are MEISTER_ROLE shorthands and deliberately
            // not plan words: a plan that says what a box is should say it.
            other => bail!("unknown role {other:?}; a plan knows cloud, cluster, agent and addons"),
        })
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Metal or context, and the whole difference is how a push reaches it.
///
/// A node that names a `disk` is a box this flake builds an image FOR:
/// `nixos-rebuild switch --target-host` moves it forward, and NixOS owns the
/// rollback. A node without one is a VM somebody else instantiated — the
/// OpenNebula fleet of `lab/LAB.md` — and the push is rsync plus a unit
/// restart, exactly what `deploy/push.sh` does today.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Metal,
    Context,
}

impl std::fmt::Display for Kind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Kind::Metal => "metal",
            Kind::Context => "context",
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    fleet: FleetHeader,
    #[serde(default)]
    defaults: Defaults,
    #[serde(default)]
    node: Vec<RawNode>,
    #[serde(default)]
    opennebula: Option<OpenNebula>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetHeader {
    pub name: String,
    /// The dns domain the nodes are named in. Kanidm needs a NAME rather than
    /// an address (its origin is an https url and its certificate has to
    /// match), so this is what an `addons` node's issuer is built from.
    #[serde(default)]
    pub domain: Option<String>,
    /// Where `tools/meister-ca` keeps its directory. Never in an image.
    #[serde(default = "default_ca")]
    pub ca: String,
}

fn default_ca() -> String {
    "pki".to_string()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Defaults {
    #[serde(default = "default_roles")]
    pub roles: Vec<String>,
    #[serde(default = "default_ssh_user")]
    pub ssh_user: String,
    /// How wide the net is. Present = the metal nodes get their `address`
    /// configured statically; absent = they come up on dhcp and the address
    /// is what the operator reserved for them. Read by `nix/fleet.nix`; here
    /// so that a key the plan may carry is not a typo to this parser.
    #[serde(default)]
    pub prefix: Option<u8>,
    #[serde(default)]
    pub gateway: Option<String>,
    #[serde(default)]
    pub nameservers: Option<Vec<String>>,
    #[serde(default)]
    pub interface: Option<String>,
}

impl Default for Defaults {
    fn default() -> Self {
        Defaults {
            roles: default_roles(),
            ssh_user: default_ssh_user(),
            prefix: None,
            gateway: None,
            nameservers: None,
            interface: None,
        }
    }
}

fn default_roles() -> Vec<String> {
    vec!["agent".to_string()]
}

fn default_ssh_user() -> String {
    "root".to_string()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenNebula {
    pub frontend: String,
    /// The name of the registered generic image, for the sentence a rollout
    /// prints. Nothing here talks XML-RPC — the vm lifecycle is out of scope.
    #[serde(default)]
    pub image: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawNode {
    name: String,
    #[serde(default)]
    group: Option<String>,
    #[serde(default)]
    roles: Option<Vec<String>>,
    address: String,
    #[serde(default)]
    ssh_user: Option<String>,
    #[serde(default)]
    disk: Option<String>,
    #[serde(default)]
    data: Option<String>,
    /// Which interface carries `address` on this box, when the plan
    /// configures addresses at all. `nix/fleet.nix` reads it.
    #[serde(default)]
    interface: Option<String>,
    /// Files of the operator's own, relative to this plan: a driver, a
    /// firmware, a kernel option, a hardware-configuration.nix. `nix/fleet.nix`
    /// imports them into that node's system next to ours. Almost every real
    /// box needs one, and none of it is something this stack models.
    #[serde(default)]
    modules: Vec<String>,
    #[serde(default)]
    labels: BTreeMap<String, String>,
    /// Free-form TOML per role, handed to `meisterstack.<role>.settings`
    /// verbatim. Nothing here validates a key — the binaries do that at
    /// start-up with `deny_unknown_fields`, which is the same rule
    /// `nix/controllers.nix` follows.
    #[serde(default)]
    settings: BTreeMap<String, toml::Table>,
    /// Overrides for the two derived endpoint lists. Present because a plan
    /// may name a controller this plan does not contain (a node that joins a
    /// cluster somewhere else); absent is the normal case.
    #[serde(default)]
    controller_addrs: Option<Vec<String>>,
    #[serde(default)]
    cloud_addrs: Option<Vec<String>>,
}

#[derive(Debug, Clone)]
pub struct Node {
    pub name: String,
    pub group: String,
    pub roles: Vec<Role>,
    pub address: String,
    pub ssh_user: String,
    pub disk: Option<String>,
    pub data: Option<String>,
    pub interface: Option<String>,
    pub modules: Vec<String>,
    pub labels: BTreeMap<String, String>,
    pub settings: BTreeMap<String, toml::Table>,
    controller_addrs: Option<Vec<String>>,
    cloud_addrs: Option<Vec<String>>,
}

impl Node {
    pub fn has(&self, role: Role) -> bool {
        self.roles.contains(&role)
    }

    pub fn kind(&self) -> Kind {
        match self.disk {
            Some(_) => Kind::Metal,
            None => Kind::Context,
        }
    }

    /// Which wave this node rolls in: the LAST of its roles. A box that is
    /// cloud, cluster, agent and addons at once is deployed once, and after
    /// everything it serves — a `push all` that restarted it first would take
    /// the whole plan down with it.
    pub fn wave_role(&self) -> Role {
        self.roles.iter().copied().max().unwrap_or(Role::Agent)
    }

    pub fn roles_csv(&self) -> String {
        self.roles
            .iter()
            .map(|r| r.as_str())
            .collect::<Vec<_>>()
            .join(",")
    }
}

#[derive(Debug, Clone)]
pub struct Plan {
    pub fleet: FleetHeader,
    pub defaults: Defaults,
    pub nodes: Vec<Node>,
    pub opennebula: Option<OpenNebula>,
}

/// One step of a rollout: a role, a raft group, and the nodes of that group in
/// the order they are taken. The list is walked ONE node at a time with a
/// health check in between (`push` waits), which is what keeps a three-member
/// group from losing quorum to its own deployment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wave {
    pub role: Role,
    pub group: String,
    pub nodes: Vec<String>,
}

impl Plan {
    pub fn load(path: &Path) -> Result<Plan> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading the plan {}", path.display()))?;
        Plan::parse(&text).with_context(|| format!("in {}", path.display()))
    }

    pub fn parse(text: &str) -> Result<Plan> {
        let raw: Raw = toml::from_str(text).context("this is not a fleet.toml")?;

        let mut nodes = Vec::new();
        for n in &raw.node {
            let role_names = n
                .roles
                .clone()
                .unwrap_or_else(|| raw.defaults.roles.clone());
            if role_names.is_empty() {
                bail!(
                    "node {:?} has no role; a node that is nothing is not a plan",
                    n.name
                );
            }
            let mut roles = Vec::new();
            for r in &role_names {
                let role = Role::parse(r).with_context(|| format!("node {:?}", n.name))?;
                if !roles.contains(&role) {
                    roles.push(role);
                }
            }
            roles.sort();
            nodes.push(Node {
                name: n.name.clone(),
                // A node alone in its group is the single-member case, and
                // that is why the default is its own name rather than a
                // shared bucket: nothing accidentally joins a raft.
                group: n.group.clone().unwrap_or_else(|| n.name.clone()),
                roles,
                address: n.address.clone(),
                ssh_user: n
                    .ssh_user
                    .clone()
                    .unwrap_or_else(|| raw.defaults.ssh_user.clone()),
                disk: n.disk.clone(),
                data: n.data.clone(),
                interface: n.interface.clone(),
                modules: n.modules.clone(),
                labels: n.labels.clone(),
                settings: n.settings.clone(),
                controller_addrs: n.controller_addrs.clone(),
                cloud_addrs: n.cloud_addrs.clone(),
            });
        }

        let plan = Plan {
            fleet: raw.fleet,
            defaults: raw.defaults,
            nodes,
            opennebula: raw.opennebula,
        };
        plan.validate()?;
        Ok(plan)
    }

    /// Everything that is wrong with a plan, said with the node's name in it.
    /// The same list `nix/fleet.nix` refuses to evaluate — a plan that builds
    /// no image should not deploy either, and the other way round.
    fn validate(&self) -> Result<()> {
        if self.nodes.is_empty() {
            bail!("the plan has no [[node]]; there is nothing to deploy");
        }
        let mut seen = BTreeSet::new();
        for n in &self.nodes {
            if !seen.insert(&n.name) {
                bail!(
                    "two nodes are called {:?}; a name is how a certificate and a hostname find each other",
                    n.name
                );
            }
            check_label(&n.name).with_context(|| format!("node {:?}", n.name))?;
            check_label(&n.group).with_context(|| format!("node {:?}: its group", n.name))?;
            if n.address.trim().is_empty() {
                bail!(
                    "node {:?} has no address; nothing can be pushed to it",
                    n.name
                );
            }
        }

        // A raft group tolerates a loss only at an odd size, and an even one
        // buys nothing: two members tolerate no loss and cost two boxes.
        for (group, members) in self.raft_groups() {
            let n = members.len();
            if !matches!(n, 1 | 3 | 5) {
                bail!(
                    "the raft group {group:?} has {n} members ({}); a group is 1, 3 or 5 — \
                     an even count tolerates exactly as many losses as the odd count below it",
                    members.join(", ")
                );
            }
        }

        let clouds: BTreeSet<&str> = self
            .nodes
            .iter()
            .filter(|n| n.has(Role::Cloud))
            .map(|n| n.group.as_str())
            .collect();
        if clouds.len() > 1 {
            bail!(
                "this plan has two clouds ({}); a fleet has one, and a cluster that is told two \
                 addresses does not know which of them is its own",
                clouds.into_iter().collect::<Vec<_>>().join(", ")
            );
        }
        let has_cluster = self.nodes.iter().any(|n| n.has(Role::Cluster));
        if !clouds.is_empty() && !has_cluster {
            bail!(
                "this plan has a cloud and no cluster; a cloud places vms on clusters and this \
                 one would have none to place on"
            );
        }

        // Every agent needs a cluster to dial, and `group` is how it names
        // one. Catching it here is the difference between a plan that is
        // wrong and a node that starts, dials nothing and looks healthy.
        for n in &self.nodes {
            if n.has(Role::Agent)
                && n.controller_addrs.is_none()
                && self.cluster_nodes(&n.group).is_empty()
            {
                bail!(
                    "agent {:?} is in the group {:?}, and no node of that group runs a cluster \
                     controller; name the cluster's group, or give the node its own \
                     controller_addrs",
                    n.name,
                    n.group
                );
            }
        }
        for n in &self.nodes {
            if n.has(Role::Cluster) && n.cloud_addrs.is_none() && self.cloud_nodes().is_empty() {
                bail!(
                    "cluster {:?} has no cloud to register with; add a node with the cloud role, \
                     or give this one its own cloud_addrs",
                    n.name
                );
            }
        }
        // D-P6. Said at the plan rather than discovered on the first boot:
        // kanidm's `domain` is an `iname` and refuses anything that starts
        // with a digit, so an addons node falling back to its ADDRESS builds
        // an image whose identity provider cannot start. Both readers of a
        // plan say it, in the same words — `nix/fleet.nix` has the twin.
        if let Some(addons) = self.addons_node()
            && self.fleet.domain.is_none()
        {
            bail!(
                "node {:?} has the addons role and this plan has no [fleet] domain; kanidm is \
                 reached under a NAME (its issuer is an https url and its certificate has to \
                 match), and an address is not one. Set [fleet] domain",
                addons.name
            );
        }
        Ok(())
    }

    pub fn node(&self, name: &str) -> Result<&Node> {
        self.nodes.iter().find(|n| n.name == name).with_context(|| {
            format!(
                "no node {name:?} in this plan; it knows {}",
                self.nodes
                    .iter()
                    .map(|n| n.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })
    }

    /// Group -> the controller replicas in it. Only cloud and cluster nodes
    /// are members of a raft: an agent names its cluster's group so that its
    /// addresses can be derived, and carries no etcd.
    pub fn raft_groups(&self) -> BTreeMap<String, Vec<String>> {
        let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for n in &self.nodes {
            if n.has(Role::Cloud) || n.has(Role::Cluster) {
                out.entry(n.group.clone()).or_default().push(n.name.clone());
            }
        }
        out
    }

    pub fn cloud_nodes(&self) -> Vec<&Node> {
        self.nodes.iter().filter(|n| n.has(Role::Cloud)).collect()
    }

    pub fn cluster_nodes(&self, group: &str) -> Vec<&Node> {
        self.nodes
            .iter()
            .filter(|n| n.has(Role::Cluster) && n.group == group)
            .collect()
    }

    pub fn addons_node(&self) -> Option<&Node> {
        self.nodes.iter().find(|n| n.has(Role::Addons))
    }

    /// The name an `addons` node is reached under.
    ///
    /// A NAME and never an address. Kanidm's origin is an https url whose
    /// certificate has to match it, and its `domain` is an `iname` — which
    /// refuses anything beginning with a digit. So the address fallback this
    /// used to have built an image that came up dead on its first boot and
    /// said so nowhere earlier (D-P6). `validate` refuses the plan instead,
    /// which is why the `None` arm here is unreachable on a parsed plan.
    pub fn addons_host(&self) -> Option<String> {
        let n = self.addons_node()?;
        self.fleet
            .domain
            .as_ref()
            .map(|d| format!("{}.{}", n.name, d))
    }

    /// What an agent of this group dials, derived: every cluster replica of
    /// its own group, on the session port.
    pub fn controller_addrs(&self, node: &Node) -> Vec<String> {
        if let Some(explicit) = &node.controller_addrs {
            return explicit.clone();
        }
        self.cluster_nodes(&node.group)
            .iter()
            .map(|c| format!("{}:{}", c.address, CLUSTER_SESSION_PORT))
            .collect()
    }

    /// What a cluster dials, derived: every replica of the cloud group.
    pub fn cloud_addrs(&self, node: &Node) -> Vec<String> {
        if let Some(explicit) = &node.cloud_addrs {
            return explicit.clone();
        }
        self.cloud_nodes()
            .iter()
            .map(|c| format!("{}:{}", c.address, CLOUD_SESSION_PORT))
            .collect()
    }

    /// `name=ip,name=ip,…` for a controller in a group of more than one, and
    /// nothing at all for a group of one: an empty peer set is exactly the
    /// loopback single member `nix/etcd.nix` bakes, and that is the shape a
    /// one-box lab has always run.
    pub fn etcd_peers(&self, node: &Node) -> Option<String> {
        if !(node.has(Role::Cloud) || node.has(Role::Cluster)) {
            return None;
        }
        let members: Vec<&Node> = self
            .nodes
            .iter()
            .filter(|n| n.group == node.group && (n.has(Role::Cloud) || n.has(Role::Cluster)))
            .collect();
        if members.len() < 2 {
            return None;
        }
        Some(
            members
                .iter()
                .map(|m| format!("{}={}", m.name, m.address))
                .collect::<Vec<_>>()
                .join(","),
        )
    }

    /// The variables this node would have been given by an OpenNebula
    /// context, derived from the plan instead. `nix/fleet.nix` bakes exactly
    /// this map into `/etc/meisterstack/context.env`, and a real context
    /// still overrides it — one renderer, two roads to it.
    pub fn context_env(&self, node: &Node) -> BTreeMap<String, String> {
        let mut env = BTreeMap::new();
        env.insert("MEISTER_ROLE".to_string(), node.roles_csv());

        if node.has(Role::Cloud) {
            env.insert("MEISTER_CLOUD_NAME".to_string(), node.group.clone());
            env.insert(
                "MEISTER_CLOUD_ADVERTISE_API".to_string(),
                format!("{}:{}", node.address, CLOUD_API_PORT),
            );
        }
        if node.has(Role::Cluster) {
            env.insert("MEISTER_CLUSTER_NAME".to_string(), node.group.clone());
            env.insert(
                "MEISTER_CLUSTER_ADVERTISE_API".to_string(),
                format!("{}:{}", node.address, CLUSTER_API_PORT),
            );
            let addrs = self.cloud_addrs(node);
            if !addrs.is_empty() {
                env.insert("MEISTER_CLOUD_ADDRS".to_string(), addrs.join(","));
            }
        }
        if node.has(Role::Agent) {
            let addrs = self.controller_addrs(node);
            if !addrs.is_empty() {
                env.insert("MEISTER_CONTROLLER_ADDRS".to_string(), addrs.join(","));
            }
        }
        if let Some(peers) = self.etcd_peers(node) {
            env.insert("MEISTER_ETCD_PEERS".to_string(), peers);
            env.insert("MEISTER_ETCD_MEMBER".to_string(), node.name.clone());
            // Two tiers bootstrapping on one network must not share a token:
            // it is what keeps a cloud member out of a cluster's raft.
            env.insert(
                "MEISTER_ETCD_TOKEN".to_string(),
                format!("{}-{}", self.fleet.name, node.group),
            );
        }

        // Where the signals go and who signs the tokens: a plan with an
        // addons node points the whole fleet at it, including the addons node
        // itself. A plan without one says nothing, and a fleet that says
        // nothing exports nothing — the shape this lab ran before Image 58.
        if let Some(addons) = self.addons_node() {
            env.insert(
                "MEISTER_OTLP_ENDPOINT".to_string(),
                format!("http://{}:{}", addons.address, OTLP_PORT),
            );
            env.insert(
                "MEISTER_LOKI_URL".to_string(),
                format!("http://{}:{}/loki/api/v1/push", addons.address, LOKI_PORT),
            );
            env.insert("MEISTER_LOG_FORMAT".to_string(), "json".to_string());
            // The addons node is reached under a NAME wherever the plan has
            // a domain, and an issuer url cannot be flattened to an address:
            // the name in the certificate, Kanidm's origin and every oauth2
            // redirect are that same name. A fleet with no dns has to be
            // told it — every node, because the addons node's own origin is
            // the name as well. It is a context value and not a
            // `networking.hosts` entry so that /etc/hosts keeps ONE owner
            // (one-context, the same one resolv.conf has).
            let host = self.addons_host().expect("an addons node was just found");
            if host != addons.address {
                env.insert(
                    "MEISTER_HOSTS".to_string(),
                    format!("{} {}", addons.address, host),
                );
            }
            if node.has(Role::Cloud) {
                // Kanidm publishes one issuer per oauth2 client, and the
                // cloud's client is the cli's.
                env.insert(
                    "MEISTER_OIDC_ISSUER".to_string(),
                    format!("https://{host}:{KANIDM_PORT}/oauth2/openid/meister-cli"),
                );
                // Kanidm writes the NAME OF THE CLIENT into `aud` and has no
                // audience mapper to say anything else with — where
                // Keycloak's mapper said "meister". The cloud checks this
                // string, so it travels with the issuer.
                env.insert(
                    "MEISTER_OIDC_AUDIENCE".to_string(),
                    "meister-cli".to_string(),
                );
                env.insert(
                    "MEISTER_OIDC_CA".to_string(),
                    "/opt/meisterstack/pki/ca.crt".to_string(),
                );
            }
        }
        env
    }

    /// What Prometheus scrapes: one port per node and per role, because a box
    /// with two roles has two listeners (9100 cloud, 9101 cluster, 9102
    /// agent — `nix/controllers.nix` and `nix/agent.nix` chose them so that
    /// exactly this list can exist).
    pub fn scrape_targets(&self) -> Vec<String> {
        let mut out = Vec::new();
        for n in &self.nodes {
            for role in &n.roles {
                let port = match role {
                    Role::Cloud => 9100,
                    Role::Cluster => 9101,
                    Role::Agent => 9102,
                    Role::Addons => continue,
                };
                out.push(format!("{}:{}", n.address, port));
            }
        }
        out
    }

    /// The rollout, in order. Agents first, then clusters, then clouds, then
    /// addons; inside one wave the nodes of a raft group are taken one at a
    /// time. `only` narrows to a node name or a role and keeps the order.
    pub fn push_order(&self, only: Option<&str>) -> Result<Vec<Wave>> {
        let selected: Vec<&Node> = match only {
            None | Some("all") => self.nodes.iter().collect(),
            Some(sel) => match Role::parse(sel) {
                Ok(role) => self.nodes.iter().filter(|n| n.has(role)).collect(),
                // Not a role, so it has to be a node — and if it is neither,
                // `node()` says so with the list of names.
                Err(_) => vec![self.node(sel)?],
            },
        };
        if selected.is_empty() {
            bail!("nothing in this plan matches {:?}", only.unwrap_or("all"));
        }

        let mut waves: Vec<Wave> = Vec::new();
        for role in [Role::Agent, Role::Cluster, Role::Cloud, Role::Addons] {
            let mut groups: BTreeMap<String, Vec<String>> = BTreeMap::new();
            for n in selected.iter().filter(|n| n.wave_role() == role) {
                groups
                    .entry(n.group.clone())
                    .or_default()
                    .push(n.name.clone());
            }
            for (group, nodes) in groups {
                waves.push(Wave { role, group, nodes });
            }
        }
        Ok(waves)
    }
}

/// A node name is a hostname, a certificate CN and an etcd member name at
/// once, so it is a DNS label or it is nothing. The same rule the API applies
/// to object names, applied where the name is first written down.
fn check_label(s: &str) -> Result<()> {
    if s.is_empty() || s.len() > 63 {
        bail!("{s:?} is not a dns label: 1 to 63 characters");
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        bail!("{s:?} is not a dns label: lowercase letters, digits and '-'");
    }
    if s.starts_with('-') || s.ends_with('-') {
        bail!("{s:?} is not a dns label: it may not start or end with '-'");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONE_BOX: &str = r#"
[fleet]
name = "one-box"
domain = "lab.example"

[defaults]
roles = ["agent"]

[[node]]
name = "box"
group = "box"
roles = ["cloud", "cluster", "agent", "addons"]
address = "10.0.0.10"
disk = "/dev/vda"

[[node]]
name = "n1"
group = "box"
address = "10.0.0.11"
disk = "/dev/vda"

[[node]]
name = "n2"
group = "box"
address = "10.0.0.12"
disk = "/dev/vda"
"#;

    /// The lab of `lab/LAB.md`: a cloud of three, cluster-1 of three,
    /// cluster-2 alone, and five agents — the shape every derivation below
    /// has to get right at once.
    const LAB: &str = r#"
[fleet]
name = "uni-lab"

[[node]]
name = "meister-cloud"
group = "cloud"
roles = ["cloud"]
address = "10.128.1.103"

[[node]]
name = "meister-cloudb"
group = "cloud"
roles = ["cloud"]
address = "10.128.1.112"

[[node]]
name = "meister-cloudc"
group = "cloud"
roles = ["cloud"]
address = "10.128.1.113"

[[node]]
name = "meister-cluster1a"
group = "cluster-1"
roles = ["cluster"]
address = "10.128.1.104"

[[node]]
name = "meister-cluster1b"
group = "cluster-1"
roles = ["cluster"]
address = "10.128.1.110"

[[node]]
name = "meister-cluster1c"
group = "cluster-1"
roles = ["cluster"]
address = "10.128.1.111"

[[node]]
name = "meister-cluster2"
group = "cluster-2"
roles = ["cluster"]
address = "10.128.1.105"

[[node]]
name = "agent-1a"
group = "cluster-1"
address = "10.128.1.106"

[[node]]
name = "agent-1b"
group = "cluster-1"
address = "10.128.1.107"

[[node]]
name = "agent-1c"
group = "cluster-1"
address = "10.128.1.114"

[[node]]
name = "agent-2a"
group = "cluster-2"
address = "10.128.1.108"

[[node]]
name = "agent-2b"
group = "cluster-2"
address = "10.128.1.109"

[opennebula]
frontend = "10.0.8.21"
"#;

    fn lab() -> Plan {
        Plan::parse(LAB).expect("the lab plan parses")
    }

    #[test]
    fn defaults_fill_in_what_a_node_leaves_out() {
        let plan = Plan::parse(ONE_BOX).unwrap();
        let n1 = plan.node("n1").unwrap();
        assert_eq!(n1.roles, vec![Role::Agent]);
        assert_eq!(n1.ssh_user, "root");
        assert_eq!(n1.kind(), Kind::Metal);
        // No group named, no group joined: a node is alone with itself.
        let solo = Plan::parse(
            "[fleet]\nname='x'\n[[node]]\nname='a'\nroles=['cluster']\naddress='10.0.0.1'\n\
             [[node]]\nname='c'\nroles=['cloud']\naddress='10.0.0.2'\n",
        )
        .unwrap();
        assert_eq!(solo.node("a").unwrap().group, "a");
    }

    #[test]
    fn a_context_node_is_one_without_a_disk() {
        let plan = lab();
        assert_eq!(plan.node("agent-1a").unwrap().kind(), Kind::Context);
        assert_eq!(plan.opennebula.as_ref().unwrap().frontend, "10.0.8.21");
    }

    #[test]
    fn addresses_are_derived_from_the_groups_of_the_lab() {
        let plan = lab();

        // An agent dials the three replicas of ITS cluster and no other.
        assert_eq!(
            plan.controller_addrs(plan.node("agent-1a").unwrap()),
            vec![
                "10.128.1.104:50051".to_string(),
                "10.128.1.110:50051".to_string(),
                "10.128.1.111:50051".to_string()
            ]
        );
        assert_eq!(
            plan.controller_addrs(plan.node("agent-2a").unwrap()),
            vec!["10.128.1.105:50051".to_string()]
        );

        // A cluster dials the whole cloud group, whichever cluster it is.
        for cluster in ["meister-cluster1a", "meister-cluster2"] {
            assert_eq!(
                plan.cloud_addrs(plan.node(cluster).unwrap()),
                vec![
                    "10.128.1.103:50050".to_string(),
                    "10.128.1.112:50050".to_string(),
                    "10.128.1.113:50050".to_string()
                ],
                "{cluster}"
            );
        }
    }

    #[test]
    fn etcd_peers_are_the_controllers_of_the_group_and_a_group_of_one_has_none() {
        let plan = lab();
        assert_eq!(
            plan.etcd_peers(plan.node("meister-cluster1b").unwrap())
                .unwrap(),
            "meister-cluster1a=10.128.1.104,meister-cluster1b=10.128.1.110,\
             meister-cluster1c=10.128.1.111"
        );
        assert_eq!(
            plan.etcd_peers(plan.node("meister-cloud").unwrap())
                .unwrap(),
            "meister-cloud=10.128.1.103,meister-cloudb=10.128.1.112,\
             meister-cloudc=10.128.1.113"
        );
        // cluster-2 is alone, so it is the single loopback member of before.
        assert_eq!(
            plan.etcd_peers(plan.node("meister-cluster2").unwrap()),
            None
        );
        // And an agent never carries one.
        assert_eq!(plan.etcd_peers(plan.node("agent-1a").unwrap()), None);
    }

    #[test]
    fn the_context_env_of_a_cluster_replica_is_what_the_lab_sets_by_hand() {
        let plan = lab();
        let env = plan.context_env(plan.node("meister-cluster1b").unwrap());
        assert_eq!(env["MEISTER_ROLE"], "cluster");
        assert_eq!(env["MEISTER_CLUSTER_NAME"], "cluster-1");
        assert_eq!(env["MEISTER_CLUSTER_ADVERTISE_API"], "10.128.1.110:3001");
        assert_eq!(
            env["MEISTER_CLOUD_ADDRS"],
            "10.128.1.103:50050,10.128.1.112:50050,10.128.1.113:50050"
        );
        assert_eq!(env["MEISTER_ETCD_MEMBER"], "meister-cluster1b");
        assert_eq!(env["MEISTER_ETCD_TOKEN"], "uni-lab-cluster-1");
        // No addons node in this plan: no exporter, no issuer, and no empty
        // strings either — an empty otlp_endpoint is an address to a client.
        assert!(!env.contains_key("MEISTER_OTLP_ENDPOINT"));
        assert!(!env.contains_key("MEISTER_OIDC_ISSUER"));
    }

    #[test]
    fn an_addons_node_points_the_fleet_at_itself() {
        let plan = Plan::parse(ONE_BOX).unwrap();
        let env = plan.context_env(plan.node("box").unwrap());
        assert_eq!(env["MEISTER_ROLE"], "agent,cluster,cloud,addons");
        assert_eq!(env["MEISTER_OTLP_ENDPOINT"], "http://10.0.0.10:4317");
        assert_eq!(
            env["MEISTER_LOKI_URL"],
            "http://10.0.0.10:3100/loki/api/v1/push"
        );
        assert_eq!(
            env["MEISTER_OIDC_ISSUER"],
            "https://box.lab.example:8443/oauth2/openid/meister-cli"
        );
        assert_eq!(env["MEISTER_OIDC_CA"], "/opt/meisterstack/pki/ca.crt");
        assert_eq!(env["MEISTER_OIDC_AUDIENCE"], "meister-cli");
        // The two values the addons role itself needs — its own name and the
        // scrape list — are NOT here: that role is build time, so they are
        // options rather than context variables (nix/addons.nix says why).
        assert!(!env.contains_key("MEISTER_ADDONS_FQDN"));
        assert_eq!(plan.addons_host().unwrap(), "box.lab.example");
        // Both advertise addresses, and they differ by port: one variable for
        // both roles cannot be right on a box that runs both.
        assert_eq!(env["MEISTER_CLOUD_ADVERTISE_API"], "10.0.0.10:3000");
        assert_eq!(env["MEISTER_CLUSTER_ADVERTISE_API"], "10.0.0.10:3001");

        // An agent of the same plan gets the exporter but no issuer: it
        // authenticates nobody.
        let n1 = plan.context_env(plan.node("n1").unwrap());
        assert_eq!(n1["MEISTER_OTLP_ENDPOINT"], "http://10.0.0.10:4317");
        assert!(!n1.contains_key("MEISTER_OIDC_ISSUER"));
        assert_eq!(n1["MEISTER_CONTROLLER_ADDRS"], "10.0.0.10:50051");
    }

    #[test]
    fn a_named_addons_node_is_resolvable_on_every_node_of_the_fleet() {
        // The issuer is an https url with a NAME in it, and a fleet with no
        // dns resolves nothing — so the plan says the one line /etc/hosts
        // needs, to every node and not just to the cloud: the addons box
        // itself follows its own redirects.
        let plan = Plan::parse(ONE_BOX).unwrap();
        for name in ["box", "n1", "n2"] {
            let env = plan.context_env(plan.node(name).unwrap());
            assert_eq!(
                env["MEISTER_HOSTS"], "10.0.0.10 box.lab.example",
                "node {name}"
            );
        }

        // D-P6: without a domain there is no name, and the address is NOT a
        // fallback — kanidm's `domain` is an `iname` and refuses anything
        // starting with a digit, so the image built and the first boot said
        // so. The plan is refused instead, with the sentence that names the
        // key.
        let no_domain = ONE_BOX.replace("domain = \"lab.example\"\n", "");
        let refused = Plan::parse(&no_domain).unwrap_err().to_string();
        assert!(refused.contains("[fleet] domain"), "{refused}");
        assert!(refused.contains("addons role"), "{refused}");
        assert!(refused.contains("box"), "the node it is about: {refused}");

        // And a plan with no addons node at all is untouched by the rule: a
        // fleet without an identity provider needs no name for one.
        let plain = no_domain.replace(", \"addons\"", "");
        let plan = Plan::parse(&plain).expect("no addons node, no rule");
        assert_eq!(plan.addons_host(), None);
        assert!(
            !plan
                .context_env(plan.node("box").unwrap())
                .contains_key("MEISTER_HOSTS")
        );
    }

    #[test]
    fn scrape_targets_are_one_port_per_role_and_not_three_per_node() {
        let plan = lab();
        let t = plan.scrape_targets();
        assert_eq!(t.len(), 12, "twelve vms, one role each: {t:?}");
        assert!(t.contains(&"10.128.1.103:9100".to_string()));
        assert!(t.contains(&"10.128.1.104:9101".to_string()));
        assert!(t.contains(&"10.128.1.106:9102".to_string()));
    }

    #[test]
    fn the_rollout_goes_agents_clusters_clouds_and_one_group_at_a_time() {
        let plan = lab();
        let waves = plan.push_order(None).unwrap();
        let shape: Vec<(String, String, usize)> = waves
            .iter()
            .map(|w| (w.role.to_string(), w.group.clone(), w.nodes.len()))
            .collect();
        assert_eq!(
            shape,
            vec![
                ("agent".to_string(), "cluster-1".to_string(), 3),
                ("agent".to_string(), "cluster-2".to_string(), 2),
                ("cluster".to_string(), "cluster-1".to_string(), 3),
                ("cluster".to_string(), "cluster-2".to_string(), 1),
                ("cloud".to_string(), "cloud".to_string(), 3),
            ]
        );
        assert_eq!(
            waves[2].nodes,
            vec![
                "meister-cluster1a",
                "meister-cluster1b",
                "meister-cluster1c"
            ]
        );
    }

    #[test]
    fn a_node_with_every_role_rolls_last() {
        let plan = Plan::parse(ONE_BOX).unwrap();
        let waves = plan.push_order(None).unwrap();
        assert_eq!(waves.first().unwrap().nodes, vec!["n1", "n2"]);
        assert_eq!(waves.first().unwrap().role, Role::Agent);
        let last = waves.last().unwrap();
        assert_eq!(last.role, Role::Addons);
        assert_eq!(last.nodes, vec!["box"]);
        // and it is in exactly one wave, not four
        assert_eq!(
            waves
                .iter()
                .filter(|w| w.nodes.contains(&"box".to_string()))
                .count(),
            1
        );
    }

    #[test]
    fn push_narrows_to_a_role_or_to_a_node_and_keeps_the_order() {
        let plan = lab();
        let waves = plan.push_order(Some("cluster")).unwrap();
        assert_eq!(waves.len(), 2);
        assert!(waves.iter().all(|w| w.role == Role::Cluster));

        let one = plan.push_order(Some("agent-2b")).unwrap();
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].nodes, vec!["agent-2b"]);

        let err = plan.push_order(Some("nope")).unwrap_err().to_string();
        assert!(err.contains("no node \"nope\""), "{err}");
        assert!(err.contains("agent-1a"), "it lists what it knows: {err}");
    }

    #[test]
    fn two_nodes_of_one_name_are_refused() {
        let err = Plan::parse(
            "[fleet]\nname='x'\n[[node]]\nname='a'\nroles=['cluster']\naddress='1.2.3.4'\n\
             [[node]]\nname='a'\nroles=['cloud']\naddress='1.2.3.5'\n",
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("two nodes are called \"a\""), "{err}");
    }

    #[test]
    fn an_unknown_role_is_named_with_its_node() {
        let err = Plan::parse(
            "[fleet]\nname='x'\n[[node]]\nname='a'\nroles=['contrller']\naddress='1.2.3.4'\n",
        )
        .unwrap_err();
        let text = format!("{err:#}");
        assert!(text.contains("contrller"), "{text}");
        assert!(text.contains("node \"a\""), "{text}");
    }

    #[test]
    fn a_raft_group_is_one_three_or_five() {
        let two = "[fleet]\nname='x'\n\
                   [[node]]\nname='a'\ngroup='c'\nroles=['cluster']\naddress='1.2.3.4'\n\
                   [[node]]\nname='b'\ngroup='c'\nroles=['cluster']\naddress='1.2.3.5'\n\
                   [[node]]\nname='cl'\nroles=['cloud']\naddress='1.2.3.6'\n";
        let err = Plan::parse(two).unwrap_err().to_string();
        assert!(err.contains("has 2 members"), "{err}");
        assert!(err.contains("\"c\""), "{err}");
    }

    #[test]
    fn a_cloud_without_a_cluster_is_refused_and_so_is_a_second_cloud() {
        let err = Plan::parse(
            "[fleet]\nname='x'\n[[node]]\nname='a'\nroles=['cloud']\naddress='1.2.3.4'\n",
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("no cluster"), "{err}");

        let err = Plan::parse(
            "[fleet]\nname='x'\n\
             [[node]]\nname='a'\ngroup='c1'\nroles=['cloud','cluster']\naddress='1.2.3.4'\n\
             [[node]]\nname='b'\ngroup='c2'\nroles=['cloud','cluster']\naddress='1.2.3.5'\n",
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("two clouds"), "{err}");
    }

    #[test]
    fn an_agent_whose_group_has_no_cluster_is_refused() {
        let err = Plan::parse(
            "[fleet]\nname='x'\n\
             [[node]]\nname='c'\ngroup='c1'\nroles=['cloud','cluster']\naddress='1.2.3.4'\n\
             [[node]]\nname='lonely'\ngroup='c9'\nroles=['agent']\naddress='1.2.3.5'\n",
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("agent \"lonely\""), "{err}");
        assert!(err.contains("\"c9\""), "{err}");

        // …unless it names its controllers itself.
        Plan::parse(
            "[fleet]\nname='x'\n\
             [[node]]\nname='c'\ngroup='c1'\nroles=['cloud','cluster']\naddress='1.2.3.4'\n\
             [[node]]\nname='lonely'\ngroup='c9'\nroles=['agent']\naddress='1.2.3.5'\n\
             controller_addrs=['10.9.9.9:50051']\n",
        )
        .expect("an explicit list stands in for the derivation");
    }

    #[test]
    fn a_name_that_is_not_a_dns_label_is_refused_where_it_is_written_down() {
        for bad in ["Box", "box_1", "-box", "box-"] {
            let text = format!(
                "[fleet]\nname='x'\n[[node]]\nname='{bad}'\nroles=['cluster']\naddress='1.2.3.4'\n\
                 [[node]]\nname='c'\nroles=['cloud']\naddress='1.2.3.5'\n"
            );
            let err = format!("{:#}", Plan::parse(&text).unwrap_err());
            assert!(err.contains("dns label"), "{bad}: {err}");
        }
    }

    #[test]
    fn a_key_the_schema_does_not_know_is_a_typo_and_not_a_feature() {
        let err = Plan::parse(
            "[fleet]\nname='x'\n[[node]]\nname='a'\nroles=['cloud']\naddres='1.2.3.4'\n",
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("addres"), "{err:#}");
    }

    #[test]
    fn free_form_settings_survive_the_parse_untouched() {
        let plan = Plan::parse(
            "[fleet]\nname='x'\n\
             [[node]]\nname='a'\nroles=['cloud','cluster']\naddress='1.2.3.4'\n\
             settings.cloud.csr_auto_approve = true\n",
        )
        .unwrap();
        let s = &plan.node("a").unwrap().settings["cloud"];
        assert_eq!(s["csr_auto_approve"].as_bool(), Some(true));
    }
}

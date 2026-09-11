// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The five verbs.
//!
//! Each one says what it is about to do before it does it, and each failure
//! carries the name of the node it happened on — because the thing that goes
//! wrong in a fleet is never "the deployment", it is `agent-1c`.

use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};

use crate::fleet::{Kind, Node, Plan, Role};
use crate::remote::{Probe, Ssh, probe};
use crate::run::{Cmd, Runner, must};

pub struct Ctx<'a> {
    pub plan: &'a Plan,
    pub runner: &'a dyn Runner,
    pub ssh: &'a Ssh,
    /// The flake to build from — `.` normally, a path or a url for a
    /// deployment whose plan lives somewhere else.
    pub flake: String,
    /// Where the CA directory is. The plan's `ca` unless overridden.
    pub ca: String,
    /// How long to wait for a replica to come back before giving up on its
    /// group, in seconds. 0 = ask once and move on, which is what the tests
    /// and a `--dry-run` want.
    pub wait: u64,
    /// Don't touch the network at all: every table cell that needs a host
    /// says so instead.
    pub offline: bool,
}

const POLL_SECONDS: u64 = 5;

impl Ctx<'_> {
    fn probe_all(&self) -> Result<BTreeMap<String, Probe>> {
        let mut out = BTreeMap::new();
        for node in &self.plan.nodes {
            let p = if self.offline {
                Probe::default()
            } else {
                probe(self.runner, self.ssh, node)?
            };
            out.insert(node.name.clone(), p);
        }
        Ok(out)
    }

    /// The store path this plan WOULD produce for a node — evaluated, not
    /// built. `nix eval` of `.outPath` computes the same string a build would
    /// land on, which is all that a drift comparison needs, and it does not
    /// spend twenty minutes proving it. `image`/`push` are where a build
    /// actually happens.
    fn planned_system(&self, node: &Node) -> Option<String> {
        if node.kind() != Kind::Metal {
            return None;
        }
        let attr = format!(
            "{}#nixosConfigurations.{}.config.system.build.toplevel.outPath",
            self.flake, node.name
        );
        let out = self
            .runner
            .run(&Cmd::read("nix").arg("eval").arg("--raw").arg(attr))
            .ok()?;
        out.ok().then(|| out.trimmed().to_string())
    }
}

// --- plan -----------------------------------------------------------------

/// The table. Read-only from end to end: it asks every host what it is and
/// says what the plan expected, and the difference between the two columns
/// `built` and `deployed` is drift.
pub fn plan(ctx: &Ctx) -> Result<()> {
    let probes = ctx.probe_all()?;
    let mut rows = Vec::new();
    rows.push([
        "NODE".to_string(),
        "ROLES".to_string(),
        "GROUP".to_string(),
        "ADDRESS".to_string(),
        "KIND".to_string(),
        "SYSTEM".to_string(),
        "KEYS".to_string(),
        "HEALTH".to_string(),
    ]);

    for node in &ctx.plan.nodes {
        let p = &probes[&node.name];
        let planned = ctx.planned_system(node);

        let system = match (&planned, &p.system) {
            _ if ctx.offline => "-".to_string(),
            (_, None) if !p.reachable => "unreachable".to_string(),
            (_, None) => "not deployed".to_string(),
            // A context node has no nixosConfiguration to compare against:
            // its system came out of an OpenNebula image, and what moves on
            // it is the binaries under /opt, not the store path.
            (None, Some(dep)) => short_store(dep),
            (Some(want), Some(dep)) if want == dep => "current".to_string(),
            (Some(_), Some(dep)) => format!("DRIFT ({})", short_store(dep)),
        };

        let keys = if ctx.offline || !p.reachable {
            "-".to_string()
        } else {
            let missing = p.missing_keys(node);
            if missing.is_empty() {
                "ok".to_string()
            } else {
                format!("missing {}", missing.join(","))
            }
        };

        let health = if ctx.offline {
            "-".to_string()
        } else {
            match p.healthy(node) {
                Ok(()) => match p.vms {
                    0 => "ok".to_string(),
                    n => format!("ok, {n} vms"),
                },
                Err(why) => why,
            }
        };

        rows.push([
            node.name.clone(),
            node.roles_csv(),
            node.group.clone(),
            node.address.clone(),
            node.kind().to_string(),
            system,
            keys,
            health,
        ]);
    }

    print_table(&rows);
    Ok(())
}

/// `/nix/store/<32 chars>-nixos-system-…` is not a column, it is a paragraph.
/// The hash is the only part that differs between two of them.
fn short_store(path: &str) -> String {
    path.rsplit('/')
        .next()
        .map(|base| base.chars().take(8).collect::<String>())
        .unwrap_or_else(|| path.to_string())
}

fn print_table(rows: &[[String; 8]]) {
    let mut width = [0usize; 8];
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            width[i] = width[i].max(cell.chars().count());
        }
    }
    for row in rows {
        let mut line = String::new();
        for (i, cell) in row.iter().enumerate() {
            if i + 1 == row.len() {
                line.push_str(cell);
            } else {
                line.push_str(&format!("{cell:<w$}  ", w = width[i]));
            }
        }
        println!("{}", line.trim_end());
    }
}

// --- image ----------------------------------------------------------------

/// Build one output and print where it landed. `--copy` puts a copy next to
/// it under a name that says which fleet, which node and which commit — the
/// name is the whole point, because a directory of `nixos.img` files is a
/// directory of one file.
pub fn image(ctx: &Ctx, target: &str, copy_to: Option<&str>) -> Result<()> {
    let names: Vec<(String, String)> = match target {
        "all" => std::iter::once(("generic".to_string(), "control-plane-image".to_string()))
            .chain(
                ctx.plan
                    .nodes
                    .iter()
                    .filter(|n| n.kind() == Kind::Metal)
                    .map(|n| (n.name.clone(), format!("image-{}", n.name))),
            )
            .collect(),
        "generic" => vec![("generic".to_string(), "control-plane-image".to_string())],
        node => {
            let n = ctx.plan.node(node)?;
            if n.kind() != Kind::Metal {
                bail!(
                    "node {:?} names no disk, so it is a context node: it runs the generic image \
                     (`image generic`) and gets its binaries with `push`",
                    n.name
                );
            }
            vec![(n.name.clone(), format!("image-{}", n.name))]
        }
    };

    for (node, attr) in names {
        println!("==> building {attr}");
        let out = must(
            ctx.runner,
            &Cmd::read("nix")
                .arg("build")
                .arg("--no-link")
                .arg("--print-out-paths")
                .arg(format!("{}#{attr}", ctx.flake)),
        )?;
        let path = out.trimmed().to_string();
        println!("    {path}");

        if let Some(dir) = copy_to {
            let file = if node == "generic" {
                "nixos.qcow2"
            } else {
                "nixos.img"
            };
            let ext = if node == "generic" { "qcow2" } else { "img" };
            let dest = format!(
                "{dir}/meisterstack-{}-{node}-{}.{ext}",
                ctx.plan.fleet.name,
                revision(ctx)
            );
            must(
                ctx.runner,
                &Cmd::change("install", &format!("copy the image to {dest}"))
                    .arg("-D")
                    .arg("-m")
                    .arg("0644")
                    .arg(format!("{path}/{file}"))
                    .arg(&dest),
            )?;
            println!("    {dest}");
        }
    }
    Ok(())
}

/// Which commit this image was built from, for the file name. `unknown` when
/// the plan is not in a git tree, which is a name and not an error.
fn revision(ctx: &Ctx) -> String {
    let out = ctx
        .runner
        .run(&Cmd::read("git").arg("rev-parse").arg("--short").arg("HEAD"));
    match out {
        Ok(o) if o.ok() && !o.trimmed().is_empty() => o.trimmed().to_string(),
        _ => "unknown".to_string(),
    }
}

// --- push -----------------------------------------------------------------

/// The rollout. Agents, then clusters, then clouds, then addons; inside a raft
/// group ONE node at a time, and the next one is not touched until the last
/// one is healthy again.
///
/// That waiting is the entire reason this verb exists rather than a for loop
/// in a shell script: three etcd members restarted together are a cluster
/// with no quorum, and the restart that does it takes four seconds.
pub fn push(ctx: &Ctx, only: Option<&str>) -> Result<()> {
    let waves = ctx.plan.push_order(only)?;
    for wave in &waves {
        println!(
            "==> {} / group {} ({})",
            wave.role,
            wave.group,
            wave.nodes.join(", ")
        );
        for (i, name) in wave.nodes.iter().enumerate() {
            let node = ctx.plan.node(name)?;
            push_one(ctx, node)?;

            // Not after the last one: nothing is waiting on it, and a group
            // whose last member is still starting is not a failed rollout.
            if i + 1 < wave.nodes.len() {
                wait_healthy(ctx, node).with_context(|| {
                    format!(
                        "the rollout of group {:?} stopped after {:?}; the remaining {} were not \
                         touched",
                        wave.group,
                        node.name,
                        wave.nodes.len() - i - 1
                    )
                })?;
            }
        }
    }
    Ok(())
}

fn push_one(ctx: &Ctx, node: &Node) -> Result<()> {
    match node.kind() {
        // NixOS owns the switch and NixOS owns the rollback: the closure
        // travels from this store, the generation is a symlink, and
        // `nixos-rebuild --rollback` is a road that exists without us.
        Kind::Metal => {
            must(
                ctx.runner,
                &Cmd::change(
                    "nixos-rebuild",
                    &format!("switch {} to the planned system", node.name),
                )
                .arg("switch")
                .arg("--flake")
                .arg(format!("{}#{}", ctx.flake, node.name))
                .arg("--target-host")
                .arg(format!("{}@{}", node.ssh_user, node.address))
                // The lab's throwaway hosts change their key on every
                // re-instantiation, and nixos-rebuild's ssh has to be told
                // the same thing every other ssh here is told.
                .args(["--option", "log-lines", "25"]),
            )?;
        }
        // A context node's image came from OpenNebula and does not change;
        // what moves is the binaries under /opt/meisterstack, exactly as
        // deploy/push.sh has moved them since M1.
        Kind::Context => {
            for role in &node.roles {
                // A role with no unit is a role this road cannot carry, and
                // that is not a failed push. `addons` is six services baked
                // into an image, and a context node's image comes from
                // OpenNebula and does not change here — the same split
                // `Kind::Context` above is built on.
                //
                // It used to `bail!`, which made `push` exit 1 on a lab whose
                // twelve nodes had all just been rolled forward correctly:
                // the addons node is the LAST wave, so everything worked and
                // the command still said no. An operator who cannot tell a
                // green rollout from a broken one has no signal at all.
                let Some(unit) = role.unit() else {
                    println!(
                        "  --> nothing to push for the {role} role on {}: the services are baked \
                         into its image, and a context node's image comes from OpenNebula",
                        node.name
                    );
                    continue;
                };
                let binary = match role {
                    Role::Agent => "meister-agent".to_string(),
                    other => format!("meister-{other}-controller"),
                };
                let src = format!("target/x86_64-unknown-linux-musl/release/{binary}");
                must(
                    ctx.runner,
                    &ctx.ssh.rsync(
                        &format!("copy {binary} to {}", node.name),
                        &[src],
                        &format!(
                            "{}@{}:/opt/meisterstack/bin/{binary}.new",
                            node.ssh_user, node.address
                        ),
                    ),
                )?;
                // Atomic swap and restart in one round trip, so a half-copied
                // binary is never the one the unit starts.
                must(
                    ctx.runner,
                    &ctx.ssh.tell(
                        node,
                        &format!("swap in {binary} and restart {unit} on {}", node.name),
                        &format!(
                            "set -e\ncd /opt/meisterstack/bin\nmv {binary}.new {binary}\n\
                             chmod +x {binary}\nsystemctl restart {unit}.service"
                        ),
                    ),
                )?;
            }
        }
    }
    Ok(())
}

/// Ask until it is healthy or until the patience runs out. A dry run asks
/// nothing: there is nothing to come back from.
fn wait_healthy(ctx: &Ctx, node: &Node) -> Result<()> {
    if ctx.runner.dry_run() {
        println!("  would wait for {} to be healthy again", node.name);
        return Ok(());
    }
    let attempts = 1 + ctx.wait / POLL_SECONDS;
    let mut last = String::from("never asked");
    for attempt in 0..attempts {
        if attempt > 0 {
            std::thread::sleep(std::time::Duration::from_secs(POLL_SECONDS));
        }
        match probe(ctx.runner, ctx.ssh, node)?.healthy(node) {
            Ok(()) => {
                println!("  {} is healthy again", node.name);
                return Ok(());
            }
            Err(why) => last = why,
        }
    }
    bail!(
        "{} did not come back within {}s: {last}",
        node.name,
        ctx.wait
    )
}

// --- keys -----------------------------------------------------------------

/// Every certificate this plan needs, from `tools/meister-ca`, which is
/// idempotent: an existing CA is reused and an existing identity is left
/// exactly as it is. So this can be run again after adding a node, and it
/// adds that node.
pub fn keys_init(ctx: &Ctx) -> Result<()> {
    let mut cmd = Cmd::change("tools/meister-ca", "issue the plan's certificates")
        .arg("--dir")
        .arg(&ctx.ca);

    let domain = ctx.plan.fleet.domain.as_deref();
    for node in &ctx.plan.nodes {
        // The serving certificate is per HOST: it is what a client checks the
        // address against. Both names go in as SANs, because half the fleet
        // is dialled by address and the identity provider by name.
        if node.has(Role::Cloud) || node.has(Role::Cluster) || node.has(Role::Addons) {
            let mut sans = vec![node.address.clone()];
            if let Some(d) = domain {
                sans.push(format!("{}.{d}", node.name));
            }
            cmd = cmd
                .arg("--serving")
                .arg(format!("{}:{}", node.name, sans.join(",")));
        }
        // The node identity is per NODE: `CN=system:node:<id>`, and the
        // cluster checks it against the node_id in the agent's Hello.
        if node.has(Role::Agent) {
            cmd = cmd.arg("--node").arg(&node.name);
        }
    }

    // The two tier identities are per GROUP, not per host: what they
    // authorize is "this cluster" and "this cloud", and the replicas of one
    // are interchangeable by design.
    for group in cloud_groups(ctx.plan) {
        cmd = cmd.arg("--cloud-identity").arg(group);
    }
    for group in cluster_groups(ctx.plan) {
        cmd = cmd.arg("--cluster-identity").arg(group);
    }

    // Somebody has to create the first tenant and the first user, and the
    // directory cannot authorize that yet. Twice, and then left alone.
    cmd = cmd.arg("--admin").arg("root");
    must(ctx.runner, &cmd)?;

    // The three secrets that are not certificates. Generated only when
    // missing, because the cloud has already sealed Secrets with the first
    // one and a new key does not open them.
    generate_if_missing(
        ctx,
        "secrets.key",
        "the key the cloud seals a Secret with and the cluster opens it",
        32,
        false,
    )?;
    if ctx.plan.addons_node().is_some() {
        generate_if_missing(ctx, "addons-admin", "kanidm's idm_admin password", 24, true)?;
        generate_if_missing(
            ctx,
            "addons-grafana-secret",
            "grafana's oauth2 client secret",
            24,
            true,
        )?;
        let env = format!("{}/addons-garage.env", ctx.ca);
        if !exists(&env) {
            must(
                ctx.runner,
                &Cmd::change("sh", "generate garage's rpc secret and admin token")
                    .arg("-c")
                    .arg(format!(
                        "umask 077; {{ echo \"GARAGE_RPC_SECRET=$(openssl rand -hex 32)\"; \
                         echo \"GARAGE_ADMIN_TOKEN=$(openssl rand -base64 24)\"; }} > {env}"
                    )),
            )?;
        }
    }
    println!("==> the certificates are in {}", ctx.ca);
    Ok(())
}

/// A local file, asked locally: the CA directory is on this machine, and
/// routing the question through the runner would only make it a command line
/// in a log nobody reads.
fn exists(path: &str) -> bool {
    std::path::Path::new(path).exists()
}

fn generate_if_missing(ctx: &Ctx, name: &str, what: &str, bytes: u32, text: bool) -> Result<()> {
    let path = format!("{}/{name}", ctx.ca);
    if exists(&path) {
        return Ok(());
    }
    // openssl, because it is the tool meister-ca already needs and a second
    // source of randomness is a second thing to audit. umask before the
    // redirection: the file must never exist world-readable, not even for the
    // instant between creation and a chmod.
    let recipe = if text {
        format!("umask 077; openssl rand -base64 {bytes} | tr -d '\\n' > {path}")
    } else {
        format!("umask 077; openssl rand -out {path} {bytes}")
    };
    must(
        ctx.runner,
        &Cmd::change("sh", &format!("generate {name} — {what}"))
            .arg("-c")
            .arg(recipe),
    )?;
    Ok(())
}

fn cloud_groups(plan: &Plan) -> Vec<String> {
    let mut g: Vec<String> = plan
        .nodes
        .iter()
        .filter(|n| n.has(Role::Cloud))
        .map(|n| n.group.clone())
        .collect();
    g.sort();
    g.dedup();
    g
}

fn cluster_groups(plan: &Plan) -> Vec<String> {
    let mut g: Vec<String> = plan
        .nodes
        .iter()
        .filter(|n| n.has(Role::Cluster))
        .map(|n| n.group.clone())
        .collect();
    g.sort();
    g.dedup();
    g
}

/// Which file in the CA directory gets which fixed name on which host. This
/// mapping is the design, and it is here rather than in a config template for
/// the reason `deploy/push.sh` gives: a serving certificate and an identity
/// are different files on every host, and one image bakes one template for
/// all of them. So the PUSH decides which file gets the fixed name, and a
/// certificate that lands on the wrong host fails at the handshake with a
/// name in the message.
pub fn key_files(node: &Node, ca: &std::path::Path) -> Vec<(String, String)> {
    let mut out = vec![("ca.crt".to_string(), "ca.crt".to_string())];
    if node.has(Role::Cloud) || node.has(Role::Cluster) || node.has(Role::Addons) {
        out.push((format!("{}.crt", node.name), "serving.crt".to_string()));
        out.push((format!("{}.key", node.name), "serving.key".to_string()));
    }
    // identity.* has ONE fixed name and a box can be two tiers at once, so
    // there is a precedence, and it is not arbitrary: the CLUSTER's identity
    // is the one a config actually reads (`cloud_cert`, dialling the cloud),
    // while the cloud's authorizes a replica reading from a sibling — and a
    // box that is its own cloud has no sibling.
    if node.has(Role::Agent) && !node.has(Role::Cluster) {
        out.push((
            format!("system-node-{}.crt", node.name),
            "identity.crt".to_string(),
        ));
        out.push((
            format!("system-node-{}.key", node.name),
            "identity.key".to_string(),
        ));
    } else if node.has(Role::Cluster) {
        out.push((
            format!("system-cluster-{}.crt", node.group),
            "identity.crt".to_string(),
        ));
        out.push((
            format!("system-cluster-{}.key", node.group),
            "identity.key".to_string(),
        ));
    } else if node.has(Role::Cloud) {
        out.push((
            format!("system-cloud-{}.crt", node.group),
            "identity.crt".to_string(),
        ));
        out.push((
            format!("system-cloud-{}.key", node.group),
            "identity.key".to_string(),
        ));
    }
    // The one file that is the same on two tiers and is not a certificate:
    // the cloud seals a Secret's values with it and the cluster opens them.
    // It goes nowhere near an agent — a node is handed the plaintext.
    //
    // And it is OPTIONAL, which is why this is the one entry that looks at
    // the directory: `keys init` does not make it, a fleet that has never
    // sealed a Secret has none, and asking for it anyway is an rsync that
    // exits 23 in the MIDDLE of a fleet — half the nodes with new keys and
    // half without, which is the worst place to stop. deploy/push.sh has
    // said so since the key existed ("OPTIONAL and deliberately so");
    // measured in the lab on 2026-09-10, where `keys push` died at the first
    // cluster replica after three agents.
    if (node.has(Role::Cloud) || node.has(Role::Cluster)) && ca.join("secrets.key").exists() {
        out.push(("secrets.key".to_string(), "secrets.key".to_string()));
    }
    if node.has(Role::Addons) {
        for f in ["addons-admin", "addons-grafana-secret", "addons-garage.env"] {
            out.push((f.to_string(), f.to_string()));
        }
    }
    out
}

/// Who may read what this push just put on one host.
///
/// Two owners and two rules, because there are two kinds of secret in that
/// directory and they are read by different processes.
///
/// **The private keys** are `meister`'s and 0600.
/// `pki::pem::check_permissions` refuses ANY group or other bit on a private
/// key, so `root:meister 0640` would be a hard start-up error rather than a
/// careful compromise; the controllers run as `meister` and read theirs as
/// its owner, the agent runs as root and reads its own as root does.
///
/// **The addons secrets** are root's and 0600, and until now they had neither.
/// `rsync` without `-p` leaves a new file at the destination's umask — 0644,
/// root-owned — so kanidm's `idm_admin` password, grafana's OAuth2 client
/// secret and garage's RPC secret and admin token landed world-readable on
/// the box, on every `keys push`, while the certificates beside them were
/// carefully locked down. They are read by systemd itself and not by the
/// services (`LoadCredential`, `environmentFile` in `nix/addons.nix`), which
/// runs as root, so root:root 0600 is the whole answer and nothing needs a
/// group.
///
/// The glob does not have to match: `set -e` is on, and a `chmod` over a
/// pattern with no file would end this script — so the addons line is emitted
/// only for a host that is getting those files.
fn modes(node: &Node) -> String {
    let mut script = String::from(
        "set -e\ncd /opt/meisterstack/pki\nchown meister:meister ./*.key\n\
         chmod 0600 ./*.key\nchmod 0644 ./*.crt",
    );
    if node.has(Role::Addons) {
        script.push_str("\nchown root:root ./addons-*\nchmod 0600 ./addons-*");
    }
    script
}

/// How many of the files rsync was handed it actually moved, out of its own
/// itemized report.
///
/// `--itemize-changes` prints one line per file it did something to, and the
/// first character says what: `<` sent, `>` received, `.` a file whose content
/// already matched (only attributes moved), `c` created, `*` a message like
/// `*deleting`. A file rsync left completely alone prints nothing.
///
/// Only `<` and `>` count. A `.f` line is rsync saying the bytes are already
/// there, which is the answer this exists to be able to give.
fn copied(itemized: &str) -> usize {
    itemized
        .lines()
        .filter(|line| line.starts_with('<') || line.starts_with('>'))
        .count()
}

/// Put them where the templates look, and make every secret unreadable to
/// everyone but the process that needs it. See [`modes`].
pub fn keys_push(ctx: &Ctx, only: Option<&str>) -> Result<()> {
    let nodes: Vec<&Node> = match only {
        None | Some("all") => ctx.plan.nodes.iter().collect(),
        Some(name) => vec![ctx.plan.node(name)?],
    };

    // Agents first, then clusters, then clouds — the same order as a binary
    // push and for a stronger reason: a cluster that starts asking for client
    // certificates before its agents have one never sees those agents again.
    let mut ordered = nodes;
    ordered.sort_by_key(|n| n.wave_role());

    for node in ordered {
        let files = key_files(node, std::path::Path::new(&ctx.ca));
        println!(
            "==> keys -> {} ({}, {})",
            node.name,
            node.roles_csv(),
            node.address
        );
        let mut moved = 0;
        for (src, dst) in &files {
            let out = must(
                ctx.runner,
                &ctx.ssh.rsync_itemized(
                    &format!("{src} -> {}:{dst}", node.name),
                    &[format!("{}/{src}", ctx.ca)],
                    &format!(
                        "{}@{}:/opt/meisterstack/pki/{dst}",
                        node.ssh_user, node.address
                    ),
                ),
            )?;
            moved += copied(&out.stdout);
        }
        must(
            ctx.runner,
            &ctx.ssh.tell(
                node,
                &format!("set the owner and the modes on {}", node.name),
                &modes(node),
            ),
        )?;
        // What this node really got. `keys push` is the verb an operator runs
        // when they are not sure — before a demo, after an image swap — and
        // it copied all of it every time and said the same thing every time,
        // so the one question it was run to answer ("has anything changed
        // here?") was the one it did not answer. The owner and the modes are
        // set either way and are not counted: they are set on files that were
        // already right, every pass, on purpose.
        if !ctx.runner.dry_run() {
            match moved {
                0 => println!(
                    "    unchanged: all {} file(s) were already there",
                    files.len()
                ),
                n => println!("    {n} of {} file(s) copied", files.len()),
            }
        }
    }
    // Restarting from here would hit a fleet whose PKI is half distributed,
    // which is the failure the order above exists to avoid.
    println!("    no unit was restarted — `meister-deploy push` does that");
    Ok(())
}

// --- check ----------------------------------------------------------------

/// What `deploy/check.sh` asked, plus the question it could not: whether the
/// API agrees. The chaos run's D8 is the reason — a node whose unit is
/// `active` and whose redb is wedged reports healthy and can do nothing — so
/// this verb asks the cloud what it thinks of its clusters and nodes as well.
pub fn check(ctx: &Ctx, cli: Option<&[String]>) -> Result<bool> {
    let mut bad = 0usize;
    for node in &ctx.plan.nodes {
        let p = probe(ctx.runner, ctx.ssh, node)?;
        println!("== {} ({}, {})", node.name, node.roles_csv(), node.address);
        if !p.reachable {
            println!("   UNREACHABLE");
            bad += 1;
            continue;
        }
        println!(
            "   host: {}  role: {}",
            p.hostname.as_deref().unwrap_or("?"),
            p.role.as_deref().unwrap_or("<none>")
        );
        for (unit, state) in &p.units {
            // Only the units this node is supposed to run: `inactive` on a
            // unit no role here names is not news.
            if relevant(node, unit) {
                println!("   {unit}: {state}");
            }
        }
        // Only where it means something: the one image ships the etcd unit
        // to every vm, so an agent answers this question too — and its answer
        // is about a member nothing reads.
        if let Some(etcd) = &p.etcd
            && (node.has(Role::Cloud) || node.has(Role::Cluster))
        {
            println!("   etcd: {etcd}");
        }
        if node.has(Role::Agent) {
            println!(
                "   /dev/kvm: {}  vms: {}",
                if p.kvm { "present" } else { "MISSING" },
                p.vms
            );
        }
        if let Some(ram) = &p.ram {
            println!("   ram: {ram}");
        }
        if let Some(d) = &p.disk {
            // The mini-chaos run died of a full disk on an agent, and the
            // unit stayed `active` throughout.
            println!(
                "   disk /: {d}% used{}",
                if d.parse().unwrap_or(0) >= 90 {
                    "  <-- FULL"
                } else {
                    ""
                }
            );
        }
        let missing = p.missing_keys(node);
        if !missing.is_empty() {
            println!("   keys: MISSING {}", missing.join(", "));
            bad += 1;
        }
        match p.healthy(node) {
            Ok(()) => println!("   health: ok"),
            Err(why) => {
                println!("   health: {why}");
                bad += 1;
            }
        }
    }

    if let Some(argv) = cli {
        println!();
        println!("== what the cloud says");
        // `node ls` at a cloud wants to know whose nodes: a cloud has only
        // somebody else's. So the plan's cluster groups are what it is asked
        // about, one at a time.
        let mut asks: Vec<Vec<String>> = vec![vec!["cluster".to_string(), "ls".to_string()]];
        for group in cluster_groups(ctx.plan) {
            asks.push(vec![
                "node".to_string(),
                "ls".to_string(),
                "--cluster".to_string(),
                group,
            ]);
        }
        for verb in asks {
            let cmd = Cmd::read(&argv[0]).args(argv[1..].to_vec()).args(verb);
            let out = ctx.runner.run(&cmd)?;
            if out.ok() {
                for line in out.stdout.lines() {
                    println!("   {line}");
                }
            } else {
                println!("   {} failed: {}", cmd.line(), out.stderr.trim());
                bad += 1;
            }
        }
    }

    println!();
    println!(
        "==> {} node(s), {}",
        ctx.plan.nodes.len(),
        if bad == 0 {
            "nothing to report".to_string()
        } else {
            format!("{bad} finding(s)")
        }
    );
    Ok(bad == 0)
}

fn relevant(node: &Node, unit: &str) -> bool {
    if unit == "etcd" {
        return node.has(Role::Cloud) || node.has(Role::Cluster);
    }
    node.roles.iter().any(|r| match r {
        Role::Addons => matches!(
            unit,
            "kanidm" | "garage" | "prometheus" | "loki" | "tempo" | "grafana"
        ),
        other => other.unit() == Some(unit),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run::Fake;

    /// The lab of `lab/LAB.md`, as a plan: a cloud of three, cluster-1 of
    /// three, cluster-2 alone, five agents, and no disks — twelve context
    /// nodes, which is what the OpenNebula fleet is.
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
name = "agent-2a"
group = "cluster-2"
address = "10.128.1.108"
[opennebula]
frontend = "10.0.8.21"
"#;

    const ONE_BOX: &str = r#"
[fleet]
name = "one-box"
domain = "lab.example"
[[node]]
name = "box"
group = "box"
roles = ["cloud", "cluster", "agent", "addons"]
address = "10.0.0.10"
disk = "/dev/vda"
data = "/dev/vdb"
[[node]]
name = "n1"
group = "box"
address = "10.0.0.11"
disk = "/dev/vda"
"#;

    const HEALTHY_AGENT: &str = "hostname=h\nunit=meister-agent:active\n";
    const HEALTHY_CLUSTER: &str = "hostname=h\nunit=meister-cluster-controller:active\nunit=etcd:active\n\
         etcd=127.0.0.1:2379 is healthy: successfully committed proposal\n";

    fn ctx<'a>(plan: &'a Plan, runner: &'a Fake, ssh: &'a Ssh) -> Ctx<'a> {
        ctx_ca(plan, runner, ssh, "pki")
    }

    fn ctx_ca<'a>(plan: &'a Plan, runner: &'a Fake, ssh: &'a Ssh, ca: &str) -> Ctx<'a> {
        Ctx {
            plan,
            runner,
            ssh,
            flake: ".".to_string(),
            ca: ca.to_string(),
            wait: 0,
            offline: false,
        }
    }

    #[test]
    fn a_dry_run_shows_the_whole_order_and_touches_nothing() {
        let plan = Plan::parse(LAB).unwrap();
        let fake = Fake::dry();
        let ssh = Ssh::default();
        push(&ctx(&plan, &fake, &ssh), None).unwrap();

        // Only the hosts, in the order they are taken. Agents of both
        // clusters first, then the clusters, then the cloud — the bottom tier
        // always before the one that gives it orders.
        let hosts: Vec<String> = fake
            .changes()
            .iter()
            .filter(|l| l.starts_with("rsync"))
            .filter_map(|l| {
                l.split('@')
                    .nth(1)
                    .map(|s| s.split(':').next().unwrap().to_string())
            })
            .collect();
        assert_eq!(
            hosts,
            vec![
                "10.128.1.106", // agent-1a
                "10.128.1.107", // agent-1b
                "10.128.1.108", // agent-2a
                "10.128.1.104", // cluster-1a
                "10.128.1.110", // cluster-1b
                "10.128.1.111", // cluster-1c
                "10.128.1.105", // cluster-2
                "10.128.1.103", // cloud a
                "10.128.1.112", // cloud b
                "10.128.1.113", // cloud c
            ]
        );
        // A dry run asks nothing of a host either: every recorded line is one
        // that was only printed.
        assert!(
            fake.lines().iter().all(|l| l.starts_with("! ")),
            "a dry run must not probe the lab: {:?}",
            fake.lines()
        );
    }

    #[test]
    fn a_context_node_gets_rsync_and_a_restart_in_that_order() {
        let plan = Plan::parse(LAB).unwrap();
        let fake = Fake::dry();
        let ssh = Ssh::default();
        push(&ctx(&plan, &fake, &ssh), Some("agent-1a")).unwrap();
        let changes = fake.changes();
        assert_eq!(changes.len(), 2, "{changes:?}");
        assert!(
            changes[0].contains(
                "target/x86_64-unknown-linux-musl/release/meister-agent \
                 root@10.128.1.106:/opt/meisterstack/bin/meister-agent.new"
            ),
            "{}",
            changes[0]
        );
        assert!(
            changes[1].contains("mv meister-agent.new meister-agent"),
            "{}",
            changes[1]
        );
        assert!(
            changes[1].contains("systemctl restart meister-agent.service"),
            "{}",
            changes[1]
        );
    }

    #[test]
    fn a_metal_node_is_switched_by_nixos_rebuild_and_nothing_else() {
        let plan = Plan::parse(ONE_BOX).unwrap();
        let fake = Fake::dry();
        let ssh = Ssh::default();
        push(&ctx(&plan, &fake, &ssh), Some("box")).unwrap();
        let changes = fake.changes();
        assert_eq!(changes.len(), 1, "{changes:?}");
        assert!(
            changes[0]
                .starts_with("nixos-rebuild switch --flake .#box --target-host root@10.0.0.10"),
            "{}",
            changes[0]
        );
    }

    /// The addons role on a CONTEXT node has nothing to rsync — the six
    /// services are in the image — and that must not fail the push.
    ///
    /// Measured in the lab on 2026-09-10: the addons node is the last wave,
    /// so `push` rolled all twelve nodes forward correctly and then exited 1.
    /// An operator who cannot tell a green rollout from a broken one has no
    /// signal at all.
    #[test]
    fn the_addons_role_on_a_context_node_is_a_note_and_not_a_failed_push() {
        const ADDONS_CONTEXT: &str = r#"
[fleet]
name = "uni-lab"
domain = "lab"
[[node]]
name = "meister-cloud"
group = "cloud"
roles = ["cloud", "addons"]
address = "10.128.1.103"
[[node]]
name = "meister-cluster1a"
group = "cluster-1"
roles = ["cluster"]
address = "10.128.1.104"
"#;
        let plan = Plan::parse(ADDONS_CONTEXT).unwrap();
        let fake = Fake::dry();
        let ssh = Ssh::default();
        push(&ctx(&plan, &fake, &ssh), Some("meister-cloud"))
            .expect("a role this road cannot carry is not a failed rollout");
        let changes = fake.changes().join("\n");
        assert!(
            changes.contains("meister-cloud-controller"),
            "the role it CAN carry was carried: {changes}"
        );
        assert!(
            !changes.contains("meister-addons"),
            "and nothing was invented for the one it cannot: {changes}"
        );
    }

    #[test]
    fn one_replica_at_a_time_and_the_next_waits_for_the_last() {
        let plan = Plan::parse(LAB).unwrap();
        // cluster-1 has three replicas. Two health checks happen — after the
        // first and after the second — and none after the third.
        let fake = Fake::new()
            .reply("10.128.1.104 'echo", HEALTHY_CLUSTER)
            .reply("10.128.1.110 'echo", HEALTHY_CLUSTER);
        let ssh = Ssh::default();
        push(&ctx(&plan, &fake, &ssh), Some("meister-cluster1a")).unwrap();
        assert!(
            fake.lines().iter().all(|l| l.starts_with("! ")),
            "a single node needs no health check: nothing follows it"
        );

        let fake = Fake::new()
            .reply("10.128.1.104 'echo", HEALTHY_CLUSTER)
            .reply("10.128.1.110 'echo", HEALTHY_CLUSTER);
        push(&ctx(&plan, &fake, &ssh), Some("cluster")).unwrap();
        let probes = fake.lines().iter().filter(|l| !l.starts_with("! ")).count();
        assert_eq!(
            probes, 2,
            "three replicas means two waits; cluster-2 is alone and waits for nobody"
        );
    }

    #[test]
    fn a_replica_that_does_not_come_back_stops_its_group_and_says_so() {
        let plan = Plan::parse(LAB).unwrap();
        // The first replica answers, but its etcd has not rejoined.
        let fake = Fake::new().reply(
            "10.128.1.104 'echo",
            "unit=meister-cluster-controller:active\netcd=context deadline exceeded\n",
        );
        let ssh = Ssh::default();
        let err = format!(
            "{:#}",
            push(&ctx(&plan, &fake, &ssh), Some("cluster")).unwrap_err()
        );
        assert!(err.contains("meister-cluster1a"), "{err}");
        assert!(err.contains("remaining 2 were not touched"), "{err}");
        assert!(
            err.contains("deadline"),
            "the reason travels with it: {err}"
        );

        // And it really stopped: only the first replica was pushed.
        let pushed = fake
            .changes()
            .iter()
            .filter(|l| l.starts_with("rsync"))
            .count();
        assert_eq!(pushed, 1);
    }

    #[test]
    fn keys_init_asks_for_a_serving_cert_per_host_and_an_identity_per_group() {
        let plan = Plan::parse(LAB).unwrap();
        let fake = Fake::dry();
        let ssh = Ssh::default();
        let ca = tempfile::tempdir().unwrap();
        let dir = ca.path().to_str().unwrap();
        keys_init(&ctx_ca(&plan, &fake, &ssh, dir)).unwrap();
        let line = &fake.changes()[0];

        assert!(
            line.starts_with(&format!("tools/meister-ca --dir {dir}")),
            "{line}"
        );
        // Per host, with its address as a SAN.
        assert!(
            line.contains("--serving meister-cloud:10.128.1.103"),
            "{line}"
        );
        assert!(
            line.contains("--serving meister-cluster1c:10.128.1.111"),
            "{line}"
        );
        // Per GROUP, once, however many replicas it has.
        assert_eq!(line.matches("--cloud-identity cloud").count(), 1, "{line}");
        assert!(line.contains("--cluster-identity cluster-1"), "{line}");
        assert!(line.contains("--cluster-identity cluster-2"), "{line}");
        // Per agent.
        assert!(line.contains("--node agent-1a"), "{line}");
        assert!(line.contains("--node agent-2a"), "{line}");
        // An agent has no serving certificate: nothing dials it.
        assert!(!line.contains("--serving agent-1a"), "{line}");
        assert!(line.contains("--admin root"), "{line}");

        // And the key that is not a certificate. This plan has no addons
        // node, so the three addons secrets are not asked for.
        let all = fake.changes().join("\n");
        assert!(all.contains("secrets.key"), "{all}");
        assert!(!all.contains("addons-admin"), "{all}");
    }

    #[test]
    fn keys_init_of_a_one_box_adds_the_three_addons_secrets() {
        let plan = Plan::parse(ONE_BOX).unwrap();
        let fake = Fake::dry();
        let ssh = Ssh::default();
        let ca = tempfile::tempdir().unwrap();
        keys_init(&ctx_ca(&plan, &fake, &ssh, ca.path().to_str().unwrap())).unwrap();
        let all = fake.changes().join("\n");
        assert!(
            all.contains("--serving box:10.0.0.10,box.lab.example"),
            "{all}"
        );
        assert!(all.contains("addons-admin"), "{all}");
        assert!(all.contains("addons-grafana-secret"), "{all}");
        assert!(all.contains("GARAGE_RPC_SECRET"), "{all}");
    }

    #[test]
    fn every_host_gets_the_files_its_roles_name_and_no_others() {
        let plan = Plan::parse(LAB).unwrap();
        // A CA that HAS sealed a Secret; the case without one is the test
        // below.
        let ca = tempfile::tempdir().unwrap();
        std::fs::write(ca.path().join("secrets.key"), "k").unwrap();
        let names = |node: &str| {
            key_files(plan.node(node).unwrap(), ca.path())
                .into_iter()
                .map(|(src, dst)| format!("{src} -> {dst}"))
                .collect::<Vec<_>>()
        };

        assert_eq!(
            names("agent-1a"),
            vec![
                "ca.crt -> ca.crt",
                "system-node-agent-1a.crt -> identity.crt",
                "system-node-agent-1a.key -> identity.key",
            ]
        );
        assert_eq!(
            names("meister-cluster1b"),
            vec![
                "ca.crt -> ca.crt",
                "meister-cluster1b.crt -> serving.crt",
                "meister-cluster1b.key -> serving.key",
                // the GROUP's identity, shared by the three replicas
                "system-cluster-cluster-1.crt -> identity.crt",
                "system-cluster-cluster-1.key -> identity.key",
                "secrets.key -> secrets.key",
            ]
        );
        assert_eq!(
            names("meister-cloud"),
            vec![
                "ca.crt -> ca.crt",
                "meister-cloud.crt -> serving.crt",
                "meister-cloud.key -> serving.key",
                "system-cloud-cloud.crt -> identity.crt",
                "system-cloud-cloud.key -> identity.key",
                "secrets.key -> secrets.key",
            ]
        );
    }

    #[test]
    fn a_box_that_is_both_tiers_shows_the_cluster_identity() {
        // identity.* is one fixed name and this box is a cloud AND a cluster.
        // The cluster's is the one a config reads (`cloud_cert`); the cloud's
        // would authorize reading from a sibling replica, and this box has no
        // sibling.
        let plan = Plan::parse(ONE_BOX).unwrap();
        let ca = tempfile::tempdir().unwrap();
        std::fs::write(ca.path().join("secrets.key"), "k").unwrap();
        let files: Vec<String> = key_files(plan.node("box").unwrap(), ca.path())
            .into_iter()
            .map(|(src, _)| src)
            .collect();
        assert!(
            files.contains(&"system-cluster-box.crt".to_string()),
            "{files:?}"
        );
        assert!(
            !files.contains(&"system-cloud-box.crt".to_string()),
            "{files:?}"
        );
        // and the addons secrets, because this box is also the addons node
        assert!(
            files.contains(&"addons-garage.env".to_string()),
            "{files:?}"
        );
    }

    #[test]
    fn a_fleet_that_has_never_sealed_a_secret_is_not_asked_for_the_key() {
        // secrets.key is made by the cloud when the first Secret is written,
        // never by `keys init`. Asking a fleet that has none for it is an
        // rsync that exits 23 halfway through the nodes — which is exactly
        // what the lab measured. deploy/push.sh skips it the same way.
        let plan = Plan::parse(LAB).unwrap();
        let ca = tempfile::tempdir().unwrap();
        let srcs = |node: &str| {
            key_files(plan.node(node).unwrap(), ca.path())
                .into_iter()
                .map(|(src, _)| src)
                .collect::<Vec<_>>()
        };
        assert!(!srcs("meister-cloud").contains(&"secrets.key".to_string()));
        assert!(!srcs("meister-cluster1a").contains(&"secrets.key".to_string()));

        // and with one, both tiers get it again
        std::fs::write(ca.path().join("secrets.key"), "k").unwrap();
        assert!(srcs("meister-cloud").contains(&"secrets.key".to_string()));
        assert!(srcs("meister-cluster1a").contains(&"secrets.key".to_string()));
        // never an agent: a node is handed the plaintext
        assert!(!srcs("agent-1a").contains(&"secrets.key".to_string()));
    }

    #[test]
    fn keys_push_goes_bottom_tier_first_and_restarts_nothing() {
        let plan = Plan::parse(LAB).unwrap();
        let fake = Fake::dry();
        let ssh = Ssh::default();
        keys_push(&ctx(&plan, &fake, &ssh), None).unwrap();
        let changes = fake.changes();

        let first_cluster = changes
            .iter()
            .position(|l| l.contains("10.128.1.104"))
            .unwrap();
        let last_agent = changes
            .iter()
            .rposition(|l| l.contains("10.128.1.108"))
            .unwrap();
        let first_cloud = changes
            .iter()
            .position(|l| l.contains("10.128.1.103"))
            .unwrap();
        assert!(
            last_agent < first_cluster && first_cluster < first_cloud,
            "a cluster that asks for client certificates before its agents have one never sees \
             those agents again"
        );
        assert!(
            !changes.iter().any(|l| l.contains("systemctl restart")),
            "pki moves files; the binary push is what restarts"
        );
        assert!(
            changes.iter().any(|l| l.contains("chmod 0600 ./*.key")),
            "a private key with a group bit is a hard start-up error"
        );
        // No addons node in this plan, so nothing is said about files that
        // are not there: `set -e` is on and a chmod over an empty glob would
        // end the script halfway through a fleet.
        assert!(
            !changes.iter().any(|l| l.contains("./addons-")),
            "a host with no addons role is told nothing about addons secrets"
        );
    }

    /// The addons secrets are carried AND protected, like the certificates
    /// D-B6: `keys push` says whether anything moved, and rsync is what
    /// knows.
    ///
    /// The verb is run when somebody is not sure — before a demo, after an
    /// image swap — and it copied everything every time and said the same
    /// thing every time. It WAS idempotent; it simply never said so, and the
    /// one question it was run to answer went unanswered. `--itemize-changes`
    /// is rsync's own answer, and only the two characters that mean a
    /// transfer count.
    #[test]
    fn what_keys_push_really_copied_is_read_off_rsyncs_own_report() {
        // Two files that moved and one whose bytes were already there. `.f`
        // is rsync saying exactly that, and it is the line that used to be
        // invisible.
        let itemized = "\
<f+++++++++ ca.crt
<f..t...... identity.crt
.f          identity.key
";
        assert_eq!(copied(itemized), 2);

        // The run everybody hopes for: rsync printed nothing at all, because
        // it did nothing at all.
        assert_eq!(copied(""), 0);
        assert_eq!(
            copied(".f          ca.crt\n.f          identity.crt\n"),
            0,
            "a file whose content already matched is not a file that was copied"
        );

        // A message line is not a file. `*deleting` is the one this could
        // meet, and counting it would report a copy that never happened.
        assert_eq!(copied("*deleting   stale.crt\n"), 0);
    }

    /// beside them.
    ///
    /// D-D8. `keys push` has carried the three files for a while; what it did
    /// not do was set a mode on them. `rsync` without `-p` leaves a new file
    /// at the destination's umask, so kanidm's `idm_admin` password, grafana's
    /// OAuth2 client secret and garage's RPC secret and admin token landed
    /// 0644 root-owned — world-readable on the box — while `serving.key` next
    /// to them was carefully locked down on the same run.
    ///
    /// root and not `meister`: systemd itself reads them (`LoadCredential`
    /// and `environmentFile` in nix/addons.nix), and it runs as root.
    #[test]
    fn the_addons_secrets_are_carried_and_locked_down_like_the_keys() {
        let plan = Plan::parse(ONE_BOX).unwrap();
        let fake = Fake::dry();
        let ssh = Ssh::default();
        keys_push(&ctx(&plan, &fake, &ssh), None).unwrap();
        let changes = fake.changes().join("\n");

        for f in ["addons-admin", "addons-grafana-secret", "addons-garage.env"] {
            assert!(
                changes.contains(&format!("pki/{f} root@10.0.0.10:/opt/meisterstack/pki/{f}")),
                "the file travels: {changes}"
            );
        }
        assert!(
            changes.contains("chmod 0600 ./addons-*"),
            "and it is not world-readable when it arrives: {changes}"
        );
        assert!(
            changes.contains("chown root:root ./addons-*"),
            "owned by the process that reads it, which is systemd: {changes}"
        );

        // The certificates keep the rule they had: this adds an owner, it
        // does not move one.
        assert!(changes.contains("chown meister:meister ./*.key"));
        assert!(changes.contains("chmod 0600 ./*.key"));
    }

    #[test]
    fn image_builds_the_attribute_and_names_the_copy_after_the_node() {
        let plan = Plan::parse(ONE_BOX).unwrap();
        let fake = Fake::new()
            .reply("nix build", "/nix/store/abc-nixos-disk-image\n")
            .reply("git rev-parse", "deadbee\n");
        let ssh = Ssh::default();
        image(&ctx(&plan, &fake, &ssh), "box", Some("/mnt/vmstore")).unwrap();
        let lines = fake.lines();
        assert!(
            lines[0].contains("nix build --no-link --print-out-paths .#image-box"),
            "{lines:?}"
        );
        assert!(
            fake.changes()[0].contains(
                "/nix/store/abc-nixos-disk-image/nixos.img \
                 /mnt/vmstore/meisterstack-one-box-box-deadbee.img"
            ),
            "{:?}",
            fake.changes()
        );
    }

    #[test]
    fn a_context_node_has_no_image_of_its_own_and_the_error_says_what_to_do() {
        let plan = Plan::parse(LAB).unwrap();
        let fake = Fake::new();
        let ssh = Ssh::default();
        let err = image(&ctx(&plan, &fake, &ssh), "agent-1a", None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("names no disk"), "{err}");
        assert!(err.contains("image generic"), "{err}");
    }

    #[test]
    fn plan_offline_asks_nobody_anything() {
        let plan = Plan::parse(LAB).unwrap();
        let fake = Fake::new();
        let ssh = Ssh::default();
        let mut c = ctx(&plan, &fake, &ssh);
        c.offline = true;
        crate::ops::plan(&c).unwrap();
        assert!(fake.lines().is_empty(), "{:?}", fake.lines());
    }

    #[test]
    fn plan_reads_every_host_once_and_calls_a_different_store_path_drift() {
        let plan = Plan::parse(ONE_BOX).unwrap();
        let fake = Fake::new()
            // what the plan would build for `box`, and what box is running
            .reply(
                "nix eval --raw .#nixosConfigurations.box",
                "/nix/store/aaa-sys\n",
            )
            .reply(
                "10.0.0.10 '",
                "system=/nix/store/bbb-sys\nunit=meister-agent:active\n",
            )
            .reply(
                "nix eval --raw .#nixosConfigurations.n1",
                "/nix/store/ccc-sys\n",
            )
            .reply(
                "10.0.0.11 '",
                "system=/nix/store/ccc-sys\nunit=meister-agent:active\n",
            );
        let ssh = Ssh::default();
        crate::ops::plan(&ctx(&plan, &fake, &ssh)).unwrap();
        let ssh_calls = fake.lines().iter().filter(|l| l.starts_with("ssh")).count();
        assert_eq!(ssh_calls, 2, "one round trip per host: {:?}", fake.lines());
    }

    #[test]
    fn check_asks_the_api_as_well_because_active_is_not_healthy() {
        let plan = Plan::parse(LAB).unwrap();
        let fake = Fake::new().reply("10.128.1.106 'echo", HEALTHY_AGENT);
        let ssh = Ssh::default();
        let argv: Vec<String> = "meister --config cli.toml -p cloud-mtls"
            .split(' ')
            .map(str::to_string)
            .collect();
        let ok = check(&ctx(&plan, &fake, &ssh), Some(&argv)).unwrap();
        assert!(
            !ok,
            "most of this fleet answered nothing, so this is a finding"
        );
        let lines = fake.lines();
        assert!(
            lines
                .iter()
                .any(|l| l.ends_with("-p cloud-mtls cluster ls")),
            "{lines:?}"
        );
        // one `node ls` per cluster group of the plan: a cloud has only
        // somebody else's nodes, and it wants to be told whose
        assert!(
            lines
                .iter()
                .any(|l| l.ends_with("node ls --cluster cluster-1")),
            "{lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|l| l.ends_with("node ls --cluster cluster-2")),
            "{lines:?}"
        );
    }
}

// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! `FloatingIp`: the object, its row and its verbs.

use super::*;

/// The name is not read here, and that is the object's own doing: the name IS
/// the address, so the spec already carries it. What metadata is read is the
/// one number the `APPLIED` column needs.
#[derive(Deserialize)]
pub(super) struct FloatingIp {
    #[serde(default)]
    metadata: Generation,
    #[serde(default)]
    spec: FloatingIpSpec,
    #[serde(default)]
    status: Observed,
}

#[derive(Deserialize, Default)]
pub(super) struct FloatingIpSpec {
    #[serde(default)]
    tenant: String,
    #[serde(default)]
    pool: String,
    #[serde(default)]
    address: String,
    #[serde(default)]
    vm: Option<String>,
    #[serde(default)]
    router: String,
    #[serde(default, rename = "internalAddress")]
    internal_address: String,
}

pub(super) fn floating_ip_row(ip: FloatingIp) -> Vec<String> {
    vec![
        ip.spec.address,
        ip.spec.tenant,
        ip.spec.pool,
        // One column for both roads, because a reservation only ever takes
        // one: a vm holds the address itself, or a router translates it to an
        // address inside the overlay. `-` is a reservation nothing points at
        // yet, which is a real and useful state.
        match (ip.spec.vm, ip.spec.router.as_str()) {
            (Some(vm), _) => vm,
            (None, "") => "-".to_string(),
            (None, router) => format!(
                "{router} -> {}",
                or_dash(Some(ip.spec.internal_address).filter(|a| !a.is_empty()))
            ),
        },
        applied(ip.metadata.generation, ip.status.observed_generation),
    ]
}

pub async fn floating_ip(ctx: &Ctx<'_>, cmd: &FloatingIpCmd) -> Result<()> {
    match cmd {
        FloatingIpCmd::Create {
            pool,
            address,
            vm,
            router,
            internal_address,
        } => {
            let mut object = json!({
                "apiVersion": "meister.io/v1",
                "kind": "FloatingIp",
                "metadata": { "name": "" },
                "spec": {},
            });
            for (key, value) in [
                ("tenant", ctx.global.tenant.as_ref()),
                ("pool", pool.as_ref()),
                ("address", address.as_ref()),
                ("vm", vm.as_ref()),
                ("router", router.as_ref()),
                ("internalAddress", internal_address.as_ref()),
            ] {
                if let Some(v) = value {
                    object["spec"][key] = json!(v);
                }
            }
            let body = ctx.post("floatingips", object).await?;
            output::emit(ctx.global, &body, |body| {
                // The address is the result and the name, so it is the one
                // token a success prints. Pipeable into the assign that
                // usually follows.
                let created: FloatingIp =
                    serde_json::from_slice(body).context("parsing the reservation")?;
                Ok(View::line(created.spec.address))
            })
        }
        FloatingIpCmd::Assign {
            address,
            vm,
            release,
        } => {
            // `null` takes the address off the VM it is on — one call, where
            // this used to be a read, an edit and a write.
            let value = match (release, vm) {
                (true, _) => serde_json::Value::Null,
                (false, Some(vm)) => json!(vm),
                (false, None) => {
                    bail!("say which vm with --vm, or --release to take it off one")
                }
            };
            let body = ctx
                .patch("floatingips", address, json!({ "spec": { "vm": value } }))
                .await?;
            output::emit_note(
                ctx.global,
                &body,
                &or_dash(vm.clone()),
                "note: the vm's tap rules follow when it is next recreated; stopping and \
                 starting it keeps the tap it has",
            )
        }
        // `ls`, `get` and `rm` never reach here: `main::dispatch` sends the
        // three verbs that need no code per resource straight to `generic`.
        FloatingIpCmd::Read(_) | FloatingIpCmd::Rm { .. } => unreachable!("dispatched generically"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `floatingip assign` says "takes effect at the next recreate"; this
    /// column is what afterwards says whether it has.
    #[test]
    fn an_assigned_address_reads_pending_until_a_create_has_carried_it() {
        let ip = |generation: u64, observed: u64| {
            let json = format!(
                r#"{{"metadata":{{"name":"10.255.0.7","generation":{generation}}},
                     "spec":{{"tenant":"acme","pool":"lab","address":"10.255.0.7","vm":"web"}},
                     "status":{{"observedGeneration":{observed}}}}}"#
            );
            floating_ip_row(serde_json::from_str::<FloatingIp>(&json).unwrap())
        };

        // Reserved and handed down: the two numbers agree.
        assert_eq!(ip(1, 1)[4], "yes");
        // Assigned to a running VM. The cloud puts an address into a
        // `CreateVm` and nowhere else, so until that VM is created again the
        // address is real in the store and absent on the wire.
        assert_eq!(ip(2, 1)[4], "pending");
        // An address written before the pair existed reads as applied, which
        // is what it was.
        assert_eq!(ip(0, 0)[4], "yes");
        // The row is still four columns plus this one, in the order the
        // header names them.
        assert_eq!(ip(2, 1)[..4], ["10.255.0.7", "acme", "lab", "web"]);
    }

    /// The other road a reservation can take: a ROUTER translates it, and the
    /// address never reaches a guest at all. One column for both, because a
    /// reservation only ever takes one of them.
    #[test]
    fn an_address_a_router_translates_names_the_router_and_the_inside_address() {
        let row = |spec: &str| {
            let json = format!(
                r#"{{"metadata":{{"name":"198.51.100.7","generation":1}},
                     "spec":{spec},"status":{{"observedGeneration":1}}}}"#
            );
            floating_ip_row(serde_json::from_str::<FloatingIp>(&json).unwrap())
        };

        let translated = row(r#"{"tenant":"lab","pool":"ext","address":"198.51.100.7",
                "router":"lab-out","internalAddress":"10.30.0.2"}"#);
        assert_eq!(translated[3], "lab-out -> 10.30.0.2");

        // A router named and no inside address is a reservation nothing can
        // be derived from — the object says so and so does the row.
        let half =
            row(r#"{"tenant":"lab","pool":"ext","address":"198.51.100.7","router":"lab-out"}"#);
        assert_eq!(half[3], "lab-out -> -");

        // And a reservation nobody has pointed anywhere yet.
        let idle = row(r#"{"tenant":"lab","pool":"ext","address":"198.51.100.7"}"#);
        assert_eq!(idle[3], "-");
    }
}

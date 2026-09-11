// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! `FloatingIpPool`: the object, its row and its verbs.

use super::*;

#[derive(Deserialize)]
pub(super) struct FloatingPool {
    metadata: Meta,
    #[serde(default)]
    spec: FloatingPoolSpec,
}

#[derive(Deserialize, Default)]
pub(super) struct FloatingPoolSpec {
    #[serde(default)]
    cidrs: Vec<String>,
    #[serde(default)]
    public: bool,
    #[serde(default)]
    default: bool,
    #[serde(default)]
    quota: std::collections::BTreeMap<String, u32>,
    #[serde(default)]
    description: String,
}

pub(super) fn floating_pool_row(p: FloatingPool) -> Vec<String> {
    vec![
        p.metadata.name,
        joined(&p.spec.cidrs),
        if p.spec.public { "public" } else { "private" }.to_string(),
        if p.spec.default { "yes" } else { "-" }.to_string(),
        quota_column(&p.spec.quota),
        p.spec.description,
    ]
}

pub async fn floating_pool(ctx: &Ctx<'_>, cmd: &FloatingPoolCmd) -> Result<()> {
    match cmd {
        FloatingPoolCmd::Create {
            name,
            cidrs,
            public,
            default,
            description,
        } => {
            let body = ctx
                .post(
                    "floatingpools",
                    json!({
                        "apiVersion": "meister.io/v1",
                        "kind": "FloatingPool",
                        "metadata": { "name": name },
                        "spec": {
                            "cidrs": cidrs,
                            "public": public,
                            "default": default,
                            "description": description.clone().unwrap_or_default(),
                        },
                    }),
                )
                .await?;
            output::emit_line(ctx.global, &body, name)
        }
        FloatingPoolCmd::Quota {
            pool,
            tenant,
            count,
        } => {
            let body = ctx
                .patch(
                    "floatingpools",
                    pool,
                    json!({ "spec": { "quota": { tenant: count } } }),
                )
                .await?;
            output::emit_line(ctx.global, &body, &count.to_string())
        }
        // `ls`, `get` and `rm` never reach here: `main::dispatch` sends the
        // three verbs that need no code per resource straight to `generic`.
        FloatingPoolCmd::Read(_) | FloatingPoolCmd::Rm { .. } => {
            unreachable!("dispatched generically")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A quota map is one cell and stays one token, so `floatingpool ls |
    /// grep` keeps working.
    #[test]
    fn a_quota_map_is_one_comma_joined_cell() {
        let quota = std::collections::BTreeMap::from([
            ("ops".to_string(), 4_u32),
            ("web".to_string(), 1_u32),
        ]);
        assert_eq!(quota_column(&quota), "ops=4,web=1");
        assert_eq!(quota_column(&Default::default()), "-");
    }
}

// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! `User`: the object, its row and its verbs.

use super::*;

#[derive(Deserialize)]
pub(super) struct User {
    metadata: Meta,
    spec: UserSpec,
    #[serde(default)]
    status: UserStatus,
}

#[derive(Deserialize)]
pub(super) struct UserSpec {
    tenant: String,
    #[serde(default)]
    role: String,
    #[serde(default)]
    description: String,
}

#[derive(Deserialize, Default)]
pub(super) struct UserStatus {
    #[serde(default)]
    certificates: Vec<IssuedCertificate>,
}

/// Only what the table shows. The fingerprint and the serial are on the
/// object and come out of `-o json`; a column 71 characters wide, repeated
/// per certificate, is not a table.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct IssuedCertificate {
    not_after: DateTime<Utc>,
}

pub(super) fn user_row(u: User, now: DateTime<Utc>) -> Vec<String> {
    // Live ones only: an expired fingerprint is history, not a credential
    // somebody holds.
    let live: Vec<&IssuedCertificate> = u
        .status
        .certificates
        .iter()
        .filter(|c| c.not_after > now)
        .collect();
    let expiry = or_dash(
        live.iter()
            .map(|c| c.not_after)
            .min()
            .map(|t| age_until(t, now)),
    );
    vec![
        u.metadata.name,
        u.spec.role,
        u.spec.tenant,
        live.len().to_string(),
        expiry,
        u.spec.description,
    ]
}

pub async fn user(ctx: &Ctx<'_>, cmd: &UserCmd) -> Result<()> {
    match cmd {
        UserCmd::Create {
            name,
            role,
            description,
        } => {
            let Some(tenant) = ctx.global.tenant.as_deref() else {
                bail!("say whose user this is with -t/--tenant; a user belongs to one tenant");
            };
            let body = ctx
                .post(
                    "users",
                    json!({
                        "apiVersion": "meister.io/v1",
                        "kind": "User",
                        "metadata": { "name": name },
                        "spec": {
                            "tenant": tenant,
                            "role": role,
                            "description": description.clone().unwrap_or_default(),
                        },
                    }),
                )
                .await?;
            output::emit_line(ctx.global, &body, name)
        }
        UserCmd::SetRole { name, role } => {
            let body = ctx
                .patch("users", name, json!({ "spec": { "role": role } }))
                .await?;
            output::emit_note(
                ctx.global,
                &body,
                role,
                "note: what a certificate says about a role is labelling; the directory is what \
                 decides, and it decides from the next request on",
            )
        }
        // `ls`, `get` and `rm` never reach here: `main::dispatch` sends the
        // three verbs that need no code per resource straight to `generic`.
        UserCmd::Read(_) | UserCmd::Rm { .. } => unreachable!("dispatched generically"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An expired certificate is history, not a credential somebody holds.
    #[test]
    fn only_live_certificates_are_counted() {
        let now = Utc::now();
        let user: User = serde_json::from_str(&format!(
            r#"{{"metadata":{{"name":"silas"}},
                 "spec":{{"tenant":"ops","role":"admin","description":"the operator"}},
                 "status":{{"certificates":[{{"notAfter":"{}"}},{{"notAfter":"{}"}}]}}}}"#,
            (now - chrono::Duration::days(1)).to_rfc3339(),
            (now + chrono::Duration::hours(5)).to_rfc3339(),
        ))
        .unwrap();
        let row = user_row(user, now);
        assert_eq!(row[3], "1");
        assert_eq!(row[4], "5h");
    }
}

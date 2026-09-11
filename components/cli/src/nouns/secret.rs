// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! `Secret`: the verbs. There is no row — a secret's values never come
//! back, so there is nothing to tabulate but what `generic` already shows.

use super::*;

/// `secret create`, and `--replace` is the same body under PUT.
///
/// One verb for both because the resource has one rule: a spec is replaced
/// whole, never merged. A client cannot READ a secret, so it cannot
/// round-trip one either, and a merge would leave somebody unable to say
/// "this key goes".
pub async fn secret(ctx: &Ctx<'_>, cmd: &SecretCmd) -> Result<()> {
    let SecretCmd::Create {
        name,
        from_literal,
        from_file,
        description,
        replace,
    } = cmd
    else {
        unreachable!("dispatched generically")
    };
    let mut data = serde_json::Map::new();
    for pair in from_literal {
        let (key, value) = pair
            .split_once('=')
            .with_context(|| format!("--from-literal wants key=value, got {pair:?}"))?;
        insert_key(&mut data, key, value.to_string())?;
    }
    for pair in from_file {
        let (key, path) = pair
            .split_once('=')
            .with_context(|| format!("--from-file wants key=path, got {pair:?}"))?;
        // Read as TEXT, because what goes in here ends up as cloud-init and a
        // guest reads it as text. A binary file is refused by name rather
        // than base64'd silently into something nobody can use.
        let value = std::fs::read_to_string(path)
            .with_context(|| format!("reading {path} for key {key:?}"))?;
        insert_key(&mut data, key, value)?;
    }
    if data.is_empty() {
        bail!("nothing to store; name at least one --from-literal or --from-file");
    }
    let object = json!({
        "apiVersion": "meister.io/v1",
        "kind": "Secret",
        "metadata": { "name": name },
        "spec": {
            "tenant": ctx.global.tenant.clone().unwrap_or_default(),
            "data": data,
            "description": description.clone().unwrap_or_default(),
        },
    });
    let body = if *replace {
        ctx.client
            .put(
                &ctx.path("secrets", Some(name))?,
                Some(serde_json::to_vec(&object)?),
            )
            .await?
    } else {
        ctx.post("secrets", object).await?
    };
    output::emit_line(ctx.global, &body, name)
}

/// One key, refused rather than silently overwritten.
///
/// `--from-literal k=a --from-file k=b` is a command whose author believes
/// one of them, and picking a winner by argument order would be the kind of
/// answer nobody can debug from the shell history.
pub(super) fn insert_key(
    data: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
    value: String,
) -> Result<()> {
    if data.contains_key(key) {
        bail!("key {key:?} was given twice");
    }
    data.insert(key.to_string(), json!(value));
    Ok(())
}

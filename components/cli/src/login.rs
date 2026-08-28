// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! `meister login` — sugar over the certificatesigningrequests flow.
//!
//! Sugar, and nothing more: every step is a call an operator could make by
//! hand with `cloud csr`. What it saves is the part nobody wants to do by
//! hand, which is generating a key pair and then not sending it.
//!
//! The claim this command makes, and the reason it exists at all: **the
//! private key never leaves this machine.** It is generated here, written
//! here at 0600, and what travels is a PKCS#10 request — a public key and a
//! name, both of which the server is free to distrust and does. See
//! `pki::csr`, where the test asserts that no line of the key appears in the
//! request.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use macros::generated;
use serde::Deserialize;
use serde_json::json;

use crate::client::Client;
use crate::cloud::CSRS;
use crate::config::{Config, Target};
use crate::{GlobalArgs, LoginArgs, OutputFormat};

#[derive(Deserialize)]
struct Csr {
    metadata: Meta,
    #[serde(default)]
    status: Status,
}

#[derive(Deserialize)]
struct Meta {
    name: String,
}

#[derive(Deserialize, Default)]
struct Status {
    #[serde(default)]
    conditions: Vec<Condition>,
    #[serde(default)]
    certificate: Option<String>,
}

#[derive(Deserialize)]
struct Condition {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    reason: String,
    #[serde(default)]
    message: String,
}

/// How often to ask again while waiting for an approver. A person is on the
/// other end of this; a second is patient enough for them and cheap enough
/// for the API.
const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

#[generated(model = ClaudeOpus, version = "5")]
pub async fn run(
    config: &Config,
    target: &Target,
    args: &LoginArgs,
    global: &GlobalArgs,
) -> Result<()> {
    let user = match &args.user {
        Some(name) => name.clone(),
        None => std::env::var("USER")
            .ok()
            .filter(|s| !s.is_empty())
            .context("no --user given and $USER is not set")?,
    };
    let (key_path, cert_path, from_profile) = destination(config, target, args)?;

    // Generated here, and this is the only place the private half exists.
    let made = pki::generate_key_and_csr(&user)?;

    let client = Client::new(target)?;
    let object = json!({
        "apiVersion": "meister.io/v1",
        "kind": "CertificateSigningRequest",
        // Empty name = let the server derive one, from the user and the
        // object's own uid. Requests happen to the same person repeatedly,
        // and a name this side picked would collide with its own last one.
        "metadata": { "name": "" },
        "spec": { "request": made.csr_pem, "username": user },
    });
    let created: Csr = serde_json::from_slice(
        &client
            .post(CSRS, Some(serde_json::to_vec(&object)?))
            .await?,
    )
    .context("parsing the created request")?;
    let name = created.metadata.name.clone();
    eprintln!("request {name} submitted for {user}");

    let issued = match certificate(&created.status)? {
        Some(pem) => pem,
        None => wait_for_approval(&client, &name, args.wait_secs).await?,
    };

    // The key first: a certificate on disk whose key is missing is a puzzle,
    // a key whose certificate is missing is a re-run of this command.
    pki::write_secret(&key_path, &made.key_pem)
        .with_context(|| format!("writing {}", key_path.display()))?;
    std::fs::write(&cert_path, &issued)
        .with_context(|| format!("writing {}", cert_path.display()))?;

    // Read back from disk rather than parsed from the string in hand: what
    // gets reported is what a client will actually present.
    let written = pki::load_certs(&cert_path)?;
    let leaf = written.first().context("the issued certificate is empty")?;
    let info = pki::CertInfo::parse(leaf)?;

    match global.output {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "request": name,
                "user": info.common_name,
                "groups": info.organizations,
                "fingerprint": info.fingerprint,
                "notAfter": info.not_after,
                "cert": cert_path,
                "key": key_path,
            }))?
        ),
        OutputFormat::Table => {
            println!("{}", info.common_name);
            eprintln!(
                "  groups      {}\n  expires     {}\n  fingerprint {}\n  cert        {}\n  \
                 key         {}",
                if info.organizations.is_empty() {
                    "-".to_string()
                } else {
                    info.organizations.join(",")
                },
                info.not_after,
                info.fingerprint,
                cert_path.display(),
                key_path.display()
            );
            if !from_profile {
                eprintln!(
                    "\nprofile {:?} does not name these files yet; add:\n\n\
                     [profiles.{}]\n\
                     ca_cert    = {:?}\n\
                     credential = {{ type = \"mtls\", cert = {:?}, key = {:?} }}\n",
                    target.profile_name,
                    target.profile_name,
                    target
                        .ca_cert
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "pki/ca.crt".into()),
                    cert_path.display().to_string(),
                    key_path.display().to_string()
                );
            }
        }
    }
    Ok(())
}

/// Where the key and the certificate land.
///
/// The profile decides, and that is the whole of "writes it into the
/// profile": a profile whose credential already says `mtls` names two paths,
/// and login puts a fresh pair exactly there — so running it again is a
/// renewal in place and the config file is never touched. Rewriting the TOML
/// would have been the other option and it costs a comment-preserving
/// editor and every comment in the file if you skip one.
///
/// A profile that names nothing yet gets `<config dir>/pki/<profile>.{key,crt}`
/// and the fragment to paste, which is the same shape `tools/meister-ca`
/// hands out.
#[generated(model = ClaudeOpus, version = "5")]
fn destination(
    config: &Config,
    target: &Target,
    args: &LoginArgs,
) -> Result<(PathBuf, PathBuf, bool)> {
    if let Some(dir) = &args.out {
        return Ok((
            dir.join(format!("{}.key", target.profile_name)),
            dir.join(format!("{}.crt", target.profile_name)),
            false,
        ));
    }
    // What the profile DECLARES, not what this call resolved to. The
    // difference is the bootstrap case and it matters: the first login is
    // made with a bearer token, so the resolved credential is a token while
    // the two paths the certificate belongs in are still the profile's.
    if let Some((cert, key)) = config.declared_mtls(&target.profile_name) {
        return Ok((key, cert, true));
    }
    let Some(dir) = config.dir.clone() else {
        bail!(
            "nowhere to put the certificate: profile {:?} names no mtls credential and there is \
             no config file to hang a pki/ directory off. Pass --out.",
            target.profile_name
        );
    };
    let pki_dir = dir.join("pki");
    Ok((
        pki_dir.join(format!("{}.key", target.profile_name)),
        pki_dir.join(format!("{}.crt", target.profile_name)),
        false,
    ))
}

/// The certificate, if this request has one — and an error rather than a wait
/// if it never will.
#[generated(model = ClaudeOpus, version = "5")]
fn certificate(status: &Status) -> Result<Option<String>> {
    if let Some(denied) = status.conditions.iter().find(|c| c.kind == "Denied") {
        bail!(
            "the request was denied ({}){}",
            if denied.reason.is_empty() {
                "no reason given"
            } else {
                &denied.reason
            },
            if denied.message.is_empty() {
                String::new()
            } else {
                format!(": {}", denied.message)
            }
        );
    }
    if let Some(failed) = status.conditions.iter().find(|c| c.kind == "Failed") {
        bail!("signing failed: {}", failed.message);
    }
    Ok(status.certificate.clone())
}

/// Poll until somebody says yes, the request is denied, or the patience runs
/// out. With the controller's `csr_auto_approve` this is never entered.
#[generated(model = ClaudeOpus, version = "5")]
async fn wait_for_approval(client: &Client, name: &str, wait_secs: u64) -> Result<String> {
    if wait_secs == 0 {
        bail!(
            "request {name} is waiting for approval; an administrator runs \
             `meister cloud csr approve {name}`"
        );
    }
    eprintln!("waiting up to {wait_secs}s for an administrator to approve {name} ...");
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(wait_secs);
    loop {
        let csr: Csr = serde_json::from_slice(&client.get(&format!("{CSRS}/{name}")).await?)
            .context("parsing the request")?;
        if let Some(pem) = certificate(&csr.status)? {
            return Ok(pem);
        }
        if tokio::time::Instant::now() >= deadline {
            bail!(
                "request {name} is still waiting after {wait_secs}s; it stays where it is - \
                 `meister cloud csr approve {name}` and run login again"
            );
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

#[cfg(test)]
#[generated(model = ClaudeOpus, version = "5")]
mod tests {
    use super::*;

    fn status(kind: &str, reason: &str) -> Status {
        Status {
            conditions: vec![Condition {
                kind: kind.to_string(),
                reason: reason.to_string(),
                message: String::new(),
            }],
            certificate: None,
        }
    }

    /// A denial is an answer, not a reason to keep polling for two minutes.
    #[test]
    fn a_denied_request_stops_the_wait_instead_of_outlasting_it() {
        let err = certificate(&status("Denied", "NotAnEmployee")).unwrap_err();
        assert!(err.to_string().contains("NotAnEmployee"), "{err}");
        assert!(certificate(&status("Failed", "")).is_err());
    }

    #[test]
    fn an_unapproved_request_is_simply_not_there_yet() {
        assert!(certificate(&Status::default()).unwrap().is_none());
        let approved = Status {
            conditions: vec![Condition {
                kind: "Approved".into(),
                reason: String::new(),
                message: String::new(),
            }],
            certificate: Some("-----BEGIN CERTIFICATE-----".into()),
        };
        assert!(certificate(&approved).unwrap().is_some());
    }
}

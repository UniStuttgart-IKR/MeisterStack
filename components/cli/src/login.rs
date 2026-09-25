// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Certificate enrollment through CertificateSigningRequest resources.
//! The private key is generated locally; only the CSR is sent to the controller.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::json;

use crate::client::Client;

/// CSR route, available before login can authenticate resource discovery.
const CSRS: &str = "/apis/meister.io/v1/certificatesigningrequests";

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

/// Poll approval once per second.
const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

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
        // Let the server assign a unique request name.
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

    // Write the key before its certificate; the pair is not committed atomically.
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

/// Choose --out, declared mTLS paths, or <config dir>/pki/<profile>.{key,crt}.
/// Enrollment writes credential files without rewriting the TOML profile.
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
    // Use declared mTLS paths even when a bootstrap token overrides authentication.
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

/// Poll until issuance, denial or timeout.
async fn wait_for_approval(client: &Client, name: &str, wait_secs: u64) -> Result<String> {
    if wait_secs == 0 {
        bail!(
            "request {name} is waiting for approval; an administrator runs \
             `meister csr approve {name}`"
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
                 `meister csr approve {name}` and run login again"
            );
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

#[cfg(test)]
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

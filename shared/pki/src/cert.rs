// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! What a peer certificate says, and whether one of our CAs said it.
//!
//! rustls has already checked the chain by the time a request reaches a
//! handler, so re-checking here is belt and braces — but it is belt and
//! braces that can be unit-tested without a TCP socket, and the identity
//! extraction has to parse the certificate anyway. One parse, both answers.

use anyhow::{Context, Result, bail};
use chrono::{DateTime, TimeZone, Utc};
use rustls_pki_types::CertificateDer;
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

/// Everything this control plane reads out of a certificate.
///
/// The Kubernetes mapping, deliberately: CN is who you are, every O is a
/// group you are in. Nothing else in a certificate is an authorisation
/// statement here — what a name may *do* is an object in etcd, and keeping
/// those two apart is what makes a role change something other than a
/// re-issue.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertInfo {
    pub common_name: String,
    pub organizations: Vec<String>,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    /// `sha256:<hex>` of the DER — what `User.status` records, and the only
    /// handle on an issued certificate that is safe to store.
    pub fingerprint: String,
    pub serial: String,
}

/// `sha256:<hex>` over the DER bytes. The same string OpenSSL prints for
/// `-fingerprint -sha256`, lowercased and without the colons.
pub fn fingerprint(der: &[u8]) -> String {
    let digest = Sha256::digest(der);
    let mut out = String::with_capacity(7 + digest.len() * 2);
    out.push_str("sha256:");
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

impl CertInfo {
    /// Read a certificate. Says nothing about whether it is trusted — that is
    /// `verified_by`.
    pub fn parse(der: &[u8]) -> Result<Self> {
        let (_, x509) = X509Certificate::from_der(der)
            .map_err(|e| anyhow::anyhow!("unparsable certificate: {e}"))?;
        Ok(Self {
            common_name: first(x509.subject().iter_common_name()),
            organizations: all(x509.subject().iter_organization()),
            not_before: stamp(x509.validity().not_before.timestamp())?,
            not_after: stamp(x509.validity().not_after.timestamp())?,
            fingerprint: fingerprint(der),
            serial: x509.tbs_certificate.raw_serial_as_string(),
        })
    }

    /// Read a certificate, having established that one of `cas` signed it and
    /// that it is valid at `now`.
    ///
    /// The two failures are told apart on purpose. "Expired eleven days ago"
    /// is an operator's problem with a known fix; "no configured CA signed
    /// this" is somebody presenting a certificate from somewhere else, and an
    /// error that blurred them would make the second one look routine.
    pub fn verified_by(
        der: &[u8],
        cas: &[CertificateDer<'static>],
        now: DateTime<Utc>,
    ) -> Result<Self> {
        let (_, x509) = X509Certificate::from_der(der)
            .map_err(|e| anyhow::anyhow!("unparsable certificate: {e}"))?;
        let info = Self::parse(der)?;

        if now < info.not_before {
            bail!(
                "certificate for {:?} is not valid before {}",
                info.common_name,
                info.not_before
            );
        }
        if now > info.not_after {
            bail!(
                "certificate for {:?} expired at {}",
                info.common_name,
                info.not_after
            );
        }

        for ca in cas {
            let Ok((_, issuer)) = X509Certificate::from_der(ca) else {
                continue;
            };
            if x509.verify_signature(Some(issuer.public_key())).is_ok() {
                return Ok(info);
            }
        }
        bail!(
            "no configured CA signed the certificate for {:?} (issuer {})",
            info.common_name,
            x509.issuer()
        )
    }
}

fn first<'a>(mut attrs: impl Iterator<Item = &'a AttributeTypeAndValue<'a>>) -> String {
    attrs
        .next()
        .and_then(|a| a.as_str().ok())
        .unwrap_or_default()
        .to_string()
}

fn all<'a>(attrs: impl Iterator<Item = &'a AttributeTypeAndValue<'a>>) -> Vec<String> {
    attrs
        .filter_map(|a| a.as_str().ok())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// X.509 times are seconds since the epoch; chrono wants to be told that a
/// nonsense one is nonsense rather than saturating to some year.
fn stamp(secs: i64) -> Result<DateTime<Utc>> {
    Utc.timestamp_opt(secs, 0)
        .single()
        .with_context(|| format!("certificate carries an impossible time ({secs})"))
}

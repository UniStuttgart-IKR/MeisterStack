// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The signing half: a CA loaded from two PEM files, and the one thing it
//! does with a CSR.
//!
//! The rule that shapes this file: **a CSR is a public key, not a claim.**
//! Everything in it that a client could have written to its own advantage —
//! the subject, the basic constraints, the key usages, the validity — is
//! thrown away here and replaced by what the API server decided. What
//! survives from the request is the public key and nothing else, which is the
//! only part of it the client is entitled to choose.

use std::path::Path;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Duration, Utc};
use macros::generated;
use rcgen::{
    CertificateSigningRequestParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose,
};
use rustls_pki_types::CertificateDer;

use crate::cert::CertInfo;

/// The subject the API server decided this certificate gets.
///
/// One organisation, not a list, because that is what rcgen's distinguished
/// name can hold — and it is enough: the group a certificate carries is the
/// role, and a name has one of those. Reading is the general case (a peer may
/// present several O values and all of them count as groups); issuing is the
/// narrow one.
#[derive(Clone, Debug)]
pub struct Subject {
    pub common_name: String,
    pub organization: Option<String>,
}

/// A freshly signed certificate: the PEM to hand back, and what it says —
/// which is what `User.status` records so that an operator can see which
/// certificates are out there without any of them being retrievable.
pub struct Issued {
    pub pem: String,
    pub info: CertInfo,
}

pub struct Ca {
    issuer: Issuer<'static, KeyPair>,
    cert_pem: String,
    roots: Vec<CertificateDer<'static>>,
}

#[generated(model = ClaudeOpus, version = "5")]
impl Ca {
    /// Load the CA from the two paths the config names. Both are paths and
    /// never inline PEM: a key that can be pasted into a TOML file is a key
    /// that ends up in a git history.
    pub fn load(cert: &Path, key: &Path) -> Result<Self> {
        let cert_pem = std::fs::read_to_string(cert)
            .with_context(|| format!("reading the CA certificate {}", cert.display()))?;
        let key_pem = {
            // Same permission rule as every other secret in this crate.
            let _ = crate::pem::load_private_key(key)?;
            std::fs::read_to_string(key)
                .with_context(|| format!("reading the CA key {}", key.display()))?
        };
        let key_pair = KeyPair::from_pem(&key_pem)
            .with_context(|| format!("{} is not a usable private key", key.display()))?;
        let issuer = Issuer::from_ca_cert_pem(&cert_pem, key_pair)
            .with_context(|| format!("{} is not a usable CA certificate", cert.display()))?;
        let roots = crate::pem::load_certs(cert)?;
        Ok(Self {
            issuer,
            cert_pem,
            roots,
        })
    }

    /// The CA certificate itself, for handing to a client that has to trust it.
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// The CA as a trust root, for verifying what it signed.
    pub fn roots(&self) -> &[CertificateDer<'static>] {
        &self.roots
    }

    /// Sign a CSR as a client certificate for `subject`, valid for `ttl` from
    /// `now`.
    ///
    /// Client authentication only, and never a CA: a certificate this server
    /// issues must not be able to issue certificates of its own, whatever the
    /// request asked for.
    pub fn sign_csr(
        &self,
        csr_pem: &str,
        subject: &Subject,
        ttl: Duration,
        now: DateTime<Utc>,
    ) -> Result<Issued> {
        if subject.common_name.is_empty() {
            bail!("a certificate needs a subject name");
        }
        let mut request = CertificateSigningRequestParams::from_pem(csr_pem)
            .map_err(|e| anyhow::anyhow!("the certificate request does not parse: {e}"))?;

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, subject.common_name.clone());
        if let Some(org) = &subject.organization {
            dn.push(DnType::OrganizationName, org.clone());
        }
        request.params.distinguished_name = dn;
        request.params.is_ca = IsCa::NoCa;
        request.params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        request.params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        // A client certificate is identified by its subject, and a SAN a
        // client put in its own request would be a name it chose for itself.
        request.params.subject_alt_names.clear();
        // A minute of slack, because the clock that checks this certificate is
        // not the clock that issued it.
        request.params.not_before = offset(now - Duration::minutes(1))?;
        request.params.not_after = offset(now + ttl)?;

        let certificate = request
            .signed_by(&self.issuer)
            .map_err(|e| anyhow::anyhow!("signing failed: {e}"))?;
        let pem = certificate.pem();
        let info = CertInfo::parse(certificate.der())?;
        Ok(Issued { pem, info })
    }
}

fn offset(at: DateTime<Utc>) -> Result<time::OffsetDateTime> {
    time::OffsetDateTime::from_unix_timestamp(at.timestamp())
        .context("certificate validity falls outside the representable range")
}

#[cfg(test)]
#[generated(model = ClaudeOpus, version = "5")]
mod tests {
    use super::*;
    use crate::csr::generate_key_and_csr;

    /// A CA in memory, written to two files, because that is the only way
    /// `Ca::load` takes one — and the test is worth more for going through
    /// the real entry point than for being quick.
    pub(crate) fn ca_in(dir: &Path, name: &str) -> Ca {
        let key = KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::new()).unwrap();
        params.distinguished_name.push(DnType::CommonName, name);
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let cert = params.self_signed(&key).unwrap();

        std::fs::create_dir_all(dir).unwrap();
        let cert_path = dir.join(format!("{name}.crt"));
        let key_path = dir.join(format!("{name}.key"));
        std::fs::write(&cert_path, cert.pem()).unwrap();
        crate::pem::write_secret(&key_path, &key.serialize_pem()).unwrap();
        Ca::load(&cert_path, &key_path).unwrap()
    }

    fn scratch(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("meister-ca-{tag}-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The subject in the request is thrown away. This is the whole security
    /// property of the CSR flow: anybody may ask, nobody gets to say who they
    /// are while asking.
    #[test]
    fn what_the_request_claims_about_itself_is_discarded() {
        let dir = scratch("claims");
        let ca = ca_in(&dir, "meister-ca");
        // The client asks to be the superuser ...
        let asked = generate_key_and_csr("system:masters").unwrap();
        // ... and gets what the server decided.
        let issued = ca
            .sign_csr(
                &asked.csr_pem,
                &Subject {
                    common_name: "alice".into(),
                    organization: Some("meister:members".into()),
                },
                Duration::days(90),
                Utc::now(),
            )
            .unwrap();
        assert_eq!(issued.info.common_name, "alice");
        assert_eq!(
            issued.info.organizations,
            vec!["meister:members".to_string()]
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_issued_certificate_verifies_against_its_own_ca_and_no_other() {
        let dir = scratch("verify");
        let ours = ca_in(&dir, "ours");
        let theirs = ca_in(&dir, "theirs");
        let now = Utc::now();
        let asked = generate_key_and_csr("bob").unwrap();
        let issued = ours
            .sign_csr(
                &asked.csr_pem,
                &Subject {
                    common_name: "bob".into(),
                    organization: None,
                },
                Duration::days(1),
                now,
            )
            .unwrap();
        let der = crate::pem::load_certs(&{
            let p = dir.join("bob.crt");
            std::fs::write(&p, &issued.pem).unwrap();
            p
        })
        .unwrap();

        let ok = CertInfo::verified_by(&der[0], ours.roots(), now).unwrap();
        assert_eq!(ok.common_name, "bob");
        assert!(
            CertInfo::verified_by(&der[0], theirs.roots(), now).is_err(),
            "foreign CA"
        );
        // and it is not valid for ever
        let later = now + Duration::days(2);
        let err = CertInfo::verified_by(&der[0], ours.roots(), later).unwrap_err();
        assert!(err.to_string().contains("expired"), "{err}");
        std::fs::remove_dir_all(&dir).ok();
    }
}

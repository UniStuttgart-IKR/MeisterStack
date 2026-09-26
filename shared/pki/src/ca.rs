// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Load a certificate authority and sign approved public keys.
//!
//! A CSR supplies the public key. The API's approved subject, usages and validity
//! replace request-supplied attributes so a requester cannot issue its own role
//! or CA permissions.

use std::path::Path;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Duration, Utc};
use rcgen::{
    CertificateSigningRequestParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose,
};
use rustls_pki_types::CertificateDer;

use crate::cert::CertInfo;

/// Server-approved certificate subject. Issuance supports one organization;
/// peer identity parsing can read multiple organization values as groups.
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

impl Ca {
    /// Load CA certificate and private key from configured PEM files.
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

    /// Sign the approved subject as a client-authentication certificate, valid
    /// for ttl from now. Request-supplied CA permissions are not retained.
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
        // Backdate validity by one minute for clock skew.
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
mod tests {
    use super::*;
    use crate::csr::generate_key_and_csr;

    /// Write a generated CA fixture to disk and load it through the public entry point.
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

    /// Replace CSR-provided subject claims with the approved identity.
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
        // Verify expiry after the requested lifetime.
        let later = now + Duration::days(2);
        let err = CertInfo::verified_by(&der[0], ours.roots(), later).unwrap_err();
        assert!(err.to_string().contains("expired"), "{err}");
        std::fs::remove_dir_all(&dir).ok();
    }
}

// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Reading PEM off disk, and writing the one file that must never be
//! world-readable.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use macros::generated;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

/// Every certificate in a PEM file, in file order — leaf first for a chain,
/// one or more roots for a CA bundle.
#[generated(model = ClaudeOpus, version = "5")]
pub fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(path)
        .with_context(|| format!("reading certificates from {}", path.display()))?
        .collect::<std::result::Result<_, _>>()
        .with_context(|| format!("parsing certificates in {}", path.display()))?;
    if certs.is_empty() {
        bail!("{} contains no certificate", path.display());
    }
    Ok(certs)
}

/// The private key, PKCS#8 / SEC1 / PKCS#1 alike — whatever the operator's
/// openssl produced.
///
/// The permission check is here rather than at the call sites because this is
/// the one function in the crate that opens a secret, and a key the group can
/// read is a key that has left the machine already. Same rule and same
/// message as the CLI's credential loader.
#[generated(model = ClaudeOpus, version = "5")]
pub fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    check_permissions(path)?;
    PrivateKeyDer::from_pem_file(path)
        .with_context(|| format!("reading the private key {}", path.display()))
}

/// Write a secret so that only its owner can read it, and never leave a
/// readable window: created 0600 from the start rather than chmod'ed after.
#[generated(model = ClaudeOpus, version = "5")]
pub fn write_secret(path: &Path, contents: &str) -> Result<()> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    use std::io::Write;
    file.write_all(contents.as_bytes())
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

#[cfg(unix)]
#[generated(model = ClaudeOpus, version = "5")]
fn check_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let meta = std::fs::metadata(path).with_context(|| format!("reading {}", path.display()))?;
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        bail!(
            "permissions {:04o} on {} are too open; run: chmod 600 {}",
            mode,
            path.display(),
            path.display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

/// Config files name PEM paths, and a path in a config file is read relative
/// to the file that named it — so a controller's config and its `pki/`
/// directory travel as one unit, exactly as the agent's config and its data
/// directory do.
#[generated(model = ClaudeOpus, version = "5")]
pub fn resolve(base: Option<&Path>, path: &Path) -> PathBuf {
    if path.is_absolute() {
        return path.to_path_buf();
    }
    match base {
        Some(b) => b.join(path),
        None => path.to_path_buf(),
    }
}

#[cfg(test)]
#[generated(model = ClaudeOpus, version = "5")]
mod tests {
    use super::*;

    #[test]
    fn a_relative_pem_path_hangs_off_the_config_that_named_it() {
        let base = Path::new("/etc/meisterstack");
        assert_eq!(
            resolve(Some(base), Path::new("pki/ca.crt")),
            PathBuf::from("/etc/meisterstack/pki/ca.crt")
        );
        assert_eq!(
            resolve(Some(base), Path::new("/srv/ca.crt")),
            PathBuf::from("/srv/ca.crt")
        );
        assert_eq!(resolve(None, Path::new("ca.crt")), PathBuf::from("ca.crt"));
    }

    /// A key anybody on the box can read is a key that has already left it.
    #[cfg(unix)]
    #[test]
    fn a_world_readable_key_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("meister-pki-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("open.key");
        std::fs::write(&path, "not a key").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = load_private_key(&path).unwrap_err();
        assert!(err.to_string().contains("too open"), "{err}");

        // And the writer never creates one in the first place.
        let tight = dir.join("tight.key");
        write_secret(&tight, "secret").unwrap();
        let mode = std::fs::metadata(&tight).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "created 0600, not chmod'ed to it afterwards");
        std::fs::remove_dir_all(&dir).ok();
    }
}

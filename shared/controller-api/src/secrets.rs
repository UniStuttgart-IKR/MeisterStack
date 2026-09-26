// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Encrypt Secret values before persisting them in etcd.
//!
//! AES-256-GCM uses one configured 256-bit key and a fresh nonce per value.
//! Additional authenticated data binds ciphertext to `<resource>/<name>/<key>`.
//! The key remains outside etcd. There is no per-object data key or built-in key
//! rotation, and unrelated inline cloud-init data is not encrypted here.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ring::aead;
use ring::rand::SecureRandom;

/// Process-local encryption key shared by cloud and cluster when secrets
/// are mirrored. Expose seal/open operations without Debug or a raw-key accessor.
pub struct Kek {
    key: aead::LessSafeKey,
    /// Where it was read from, for the one log line at start-up. The PATH,
    /// never the bytes.
    source: PathBuf,
}

/// The one algorithm, and the length its key has to be.
const KEY_LEN: usize = 32;

impl Kek {
    /// Read exactly 32 raw key bytes or their 64-character hexadecimal encoding.
    /// Reject other lengths rather than padding or truncating key material.
    pub fn read(path: &Path) -> Result<Self> {
        let raw = std::fs::read(path)
            .with_context(|| format!("reading the secrets key {}", path.display()))?;
        let bytes = decode_key(&raw).with_context(|| {
            format!(
                "the secrets key {} is not usable; it must be {KEY_LEN} raw bytes or {} hex \
                 characters (head -c {KEY_LEN} /dev/urandom > {})",
                path.display(),
                KEY_LEN * 2,
                path.display()
            )
        })?;
        Ok(Self {
            key: aead::LessSafeKey::new(
                aead::UnboundKey::new(&aead::AES_256_GCM, &bytes)
                    .map_err(|_| anyhow::anyhow!("the key was refused by the cipher"))?,
            ),
            source: path.to_path_buf(),
        })
    }

    /// For tests and for nothing else: a key from bytes already in hand.
    pub fn from_bytes(bytes: &[u8; KEY_LEN]) -> Result<Self> {
        Ok(Self {
            key: aead::LessSafeKey::new(
                aead::UnboundKey::new(&aead::AES_256_GCM, bytes)
                    .map_err(|_| anyhow::anyhow!("the key was refused by the cipher"))?,
            ),
            source: PathBuf::from("<memory>"),
        })
    }

    /// The path this key came from. For the start-up line, which says WHERE
    /// and never what.
    pub fn source(&self) -> &Path {
        &self.source
    }

    /// Seal a value as base64(nonce || ciphertext || tag) with a fresh random nonce.
    /// Do not derive the nonce from the path: repeated writes must not reuse it.
    pub fn seal(&self, aad: &Aad, plaintext: &str) -> Result<String> {
        let mut nonce = [0u8; aead::NONCE_LEN];
        ring::rand::SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| anyhow::anyhow!("the system random source refused"))?;
        let mut buffer = plaintext.as_bytes().to_vec();
        self.key
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(aad.0.as_bytes()),
                &mut buffer,
            )
            .map_err(|_| anyhow::anyhow!("sealing failed"))?;
        let mut out = nonce.to_vec();
        out.append(&mut buffer);
        Ok(B64.encode(out))
    }

    /// Decrypt and authenticate a value against its storage slot.
    /// Empty plaintext is valid; malformed or unauthenticated ciphertext is an error.
    pub fn open(&self, aad: &Aad, sealed: &str) -> Result<String> {
        let raw = B64
            .decode(sealed.as_bytes())
            .context("the stored value is not base64")?;
        if raw.len() <= aead::NONCE_LEN {
            bail!("the stored value is too short to be a sealed one");
        }
        let (nonce, rest) = raw.split_at(aead::NONCE_LEN);
        let nonce: [u8; aead::NONCE_LEN] = nonce.try_into().expect("checked above");
        let mut buffer = rest.to_vec();
        let plaintext = self
            .key
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(aad.0.as_bytes()),
                &mut buffer,
            )
            .map_err(|_| {
                anyhow::anyhow!(
                    "this value cannot be opened for {aad}: a different key, or it was written \
                     somewhere else"
                )
            })?;
        String::from_utf8(plaintext.to_vec()).context("the sealed value was not utf-8")
    }

    /// Seal a whole map, each value into its own slot.
    pub fn seal_all(
        &self,
        resource: &str,
        name: &str,
        data: &BTreeMap<String, String>,
    ) -> Result<BTreeMap<String, String>> {
        data.iter()
            .map(|(key, value)| {
                Ok((
                    key.clone(),
                    self.seal(&Aad::of(resource, name, key), value)?,
                ))
            })
            .collect()
    }
}

/// Typed authenticated-data identity derived from resource, object name and key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Aad(String);

impl Aad {
    pub fn of(resource: &str, name: &str, key: &str) -> Self {
        Self(format!("{resource}/{name}/{key}"))
    }
}

impl std::fmt::Display for Aad {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// 32 raw bytes, or 64 hex characters with whatever whitespace an editor put
/// around them.
fn decode_key(raw: &[u8]) -> Result<[u8; KEY_LEN]> {
    if let Ok(exact) = <[u8; KEY_LEN]>::try_from(raw) {
        return Ok(exact);
    }
    let text = std::str::from_utf8(raw).context("neither 32 raw bytes nor text")?;
    let text = text.trim();
    if text.len() != KEY_LEN * 2 {
        bail!("{} characters, not {}", text.len(), KEY_LEN * 2);
    }
    let mut out = [0u8; KEY_LEN];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).context("not hex")?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kek() -> Kek {
        Kek::from_bytes(&[7u8; KEY_LEN]).expect("a key")
    }

    /// The roundtrip, and the two properties that make it worth having: the
    /// ciphertext is not the plaintext, and two seals of the SAME value
    /// differ.
    #[test]
    fn a_value_comes_back_out_and_never_twice_the_same_way() {
        let kek = kek();
        let aad = Aad::of("secrets", "db", "password");

        let sealed = kek.seal(&aad, "hunter2").expect("sealed");
        assert!(!sealed.contains("hunter2"), "not in the clear: {sealed}");
        assert_eq!(kek.open(&aad, &sealed).expect("opened"), "hunter2");

        // A fresh nonce per value, which is the one thing GCM cannot do
        // without. Equal ciphertexts would leak equality of the plaintexts.
        let again = kek.seal(&aad, "hunter2").expect("sealed");
        assert_ne!(sealed, again, "a nonce is drawn per value");
        assert_eq!(kek.open(&aad, &again).expect("opened"), "hunter2");

        // An empty value is a value, not an absence.
        let empty = kek.seal(&aad, "").expect("sealed");
        assert_eq!(kek.open(&aad, &empty).expect("opened"), "");
    }

    /// The AAD is the half that makes a ciphertext belong somewhere. Moving
    /// one — to another key, another object, another resource — fails, and
    /// fails as tampering rather than as a wrong value.
    #[test]
    fn a_value_moved_to_another_slot_will_not_open() {
        let kek = kek();
        let sealed = kek
            .seal(&Aad::of("secrets", "prod", "password"), "hunter2")
            .expect("sealed");

        for elsewhere in [
            Aad::of("secrets", "prod", "motd"),    // another key
            Aad::of("secrets", "dev", "password"), // another object
            Aad::of("images", "prod", "password"), // another resource
        ] {
            let refused = kek
                .open(&elsewhere, &sealed)
                .expect_err("the slot is part of the ciphertext");
            assert!(
                refused.to_string().contains("written somewhere else"),
                "{refused:#}"
            );
        }
        // And its own slot still opens it.
        assert_eq!(
            kek.open(&Aad::of("secrets", "prod", "password"), &sealed)
                .expect("opened"),
            "hunter2"
        );
    }

    /// Another key is another key, and the sentence does not say which of the
    /// two problems it was.
    #[test]
    fn a_different_key_opens_nothing() {
        let aad = Aad::of("secrets", "db", "password");
        let sealed = kek().seal(&aad, "hunter2").expect("sealed");
        let stranger = Kek::from_bytes(&[9u8; KEY_LEN]).expect("a key");
        assert!(stranger.open(&aad, &sealed).is_err());
    }

    /// Rubbish in the store is refused rather than panicking. It is a fact
    /// about etcd — anybody with that socket can write anything — and this is
    /// the layer that finds out.
    #[test]
    fn a_stored_value_that_is_not_a_sealed_one_is_refused() {
        let kek = kek();
        let aad = Aad::of("secrets", "db", "password");
        for rubbish in ["", "not base64!!", "aGk="] {
            assert!(kek.open(&aad, rubbish).is_err(), "{rubbish:?}");
        }
    }

    /// Both encodings, and the refusal in between. A key that was silently
    /// padded would decrypt nothing anybody had written before it.
    #[test]
    fn a_key_is_thirty_two_bytes_however_it_was_written_down() {
        let raw = [3u8; KEY_LEN];
        assert_eq!(decode_key(&raw).expect("raw"), raw);

        let hex = raw.iter().map(|b| format!("{b:02x}")).collect::<String>();
        assert_eq!(decode_key(hex.as_bytes()).expect("hex"), raw);
        assert_eq!(
            decode_key(format!("{hex}\n").as_bytes()).expect("hex with a newline"),
            raw,
            "an editor's trailing newline is not part of the key"
        );

        for bad in ["", "short", &"a".repeat(63), &"z".repeat(64)] {
            assert!(decode_key(bad.as_bytes()).is_err(), "{bad:?}");
        }
    }
}

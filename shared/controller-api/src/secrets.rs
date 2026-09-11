// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Sealing a secret's values before they reach etcd, and opening them again.
//!
//! ## Why this exists at all
//!
//! `spec.vm.cloud_init.user_data` is the only way into a guest today, it is
//! immutable, and it is PLAINTEXT in etcd — a store that is unauthenticated
//! and unencrypted in this deployment. The catalogue's fourth sharpening says
//! the rest: a `Secret` object without encryption would be `user_data` under
//! a new name, so the object and the sealing land together or neither does.
//!
//! ## The shape, and what it is not
//!
//! One key encrypts every value: AES-256-GCM, a fresh nonce per value, and
//! the value's own path as additional data. That is Kubernetes' `aesgcm`
//! provider and not a full envelope with a per-object data key — the
//! difference is what a key rotation costs, and rotation is exactly what this
//! does not have yet (there is no verb, deliberately; the report says what
//! one would need). Naming it envelope encryption is right in the sense that
//! matters here: the ciphertext is in etcd and the key is not, so an etcd
//! backup is not a pile of somebody's cloud-init.
//!
//! ## What the AAD buys
//!
//! `<resource>/<name>/<key>` travels as additional authenticated data, so a
//! ciphertext is bound to the exact slot it was written to. Without it, a
//! caller who could write one field of one object — or anybody with the etcd
//! socket, which is the threat this is actually about — could move
//! `prod/db-password` into `dev/motd` and read it back through a VM they own.
//! GCM would verify happily; the bytes are the same bytes. With it, the open
//! fails, and it fails as tampering rather than as a wrong value.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ring::aead;
use ring::rand::SecureRandom;

/// The key-encryption key, held in memory for the life of the process.
///
/// `/opt/meisterstack/pki/secrets.key` in the lab, put there by
/// `push.sh pki` on BOTH controller tiers — the cloud seals and the cluster
/// has to open, because it is the cluster that hands a node its cloud-init.
///
/// No `Debug`, no `Clone`, no accessor: the only thing that can be done with
/// this type is `seal` and `open`. A key that could be printed would
/// eventually be printed.
pub struct Kek {
    key: aead::LessSafeKey,
    /// Where it was read from, for the one log line at start-up. The PATH,
    /// never the bytes.
    source: PathBuf,
}

/// The one algorithm, and the length its key has to be.
const KEY_LEN: usize = 32;

impl Kek {
    /// Read a key from disk.
    ///
    /// Two encodings, both unambiguous because 32 raw bytes cannot also be 64
    /// hex characters: raw (what `head -c 32 /dev/urandom > secrets.key`
    /// gives) or hex (what an operator can paste into a password manager and
    /// read back). Anything else is refused by length with the sentence that
    /// says how to make one — a key that was silently padded or truncated
    /// would decrypt nothing anybody wrote before it.
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

    /// Seal one value into the slot it belongs in.
    ///
    /// The output is `base64(nonce || ciphertext || tag)`: one string, because
    /// what holds it is a JSON object in etcd, and base64 because that object
    /// is read by `jq` often enough that a byte array would be a nuisance.
    /// The nonce travels with the ciphertext rather than being derived —
    /// deriving it from the path would make two writes of the same key reuse
    /// it, which is the one thing GCM must never do.
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

    /// Open one value, checked against the slot it is being read from.
    ///
    /// An error here is tampering or a wrong key, and it is never "the value
    /// was empty": an empty plaintext seals to a perfectly good ciphertext.
    /// The sentence stays vague on purpose — which of the two it was is not
    /// something to tell whoever provoked it.
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

/// Where a value lives, as the cipher is told about it.
///
/// A type rather than a `&str` so that a caller cannot pass the value, the
/// key or the name by mistake — the whole point is that it is built from all
/// three, in one place, and read the same way on both tiers.
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

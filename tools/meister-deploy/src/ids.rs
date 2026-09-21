// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! What a contract object is called, and why it is called that.
//!
//! Three of the four ids name CONTENT: a `manifest_id`, a `release_id` and a
//! `plan_id` are a sha256 over the object's canonical JSON with its own id
//! field removed. Two consequences, and both are the point:
//!
//! * The same tree resolved twice is the same `manifest_id`, so an operator
//!   can say "this is the manifest I reviewed" rather than "this is the
//!   manifest I resolved at 14:05".
//! * Any field that changes changes the id, so an approval bound to a
//!   `plan_id` cannot silently cover a different plan. That is the whole
//!   mechanism behind `--approve destructive=<plan_id>`.
//!
//! The id field is removed before hashing because it cannot be inside its own
//! input. Removing it rather than setting it to null or to a placeholder
//! keeps one definition instead of three conventions.
//!
//! Three more fields are removed, and for one reason: they say WHERE and WITH
//! WHAT, not WHAT. `created_at` is when the question was asked. `source.
//! repo_path` is the directory the repository happened to be cloned into —
//! the same commit checked out on a CI runner is the same fleet. `tool` is
//! which build of this binary did the asking. If any of them were in the
//! hash, "this is the manifest I reviewed" would only be true on one machine
//! on one afternoon, and that sentence is the entire point of a content id.
//! Anything those three actually CHANGE about the manifest changes the
//! manifest, and therefore the id.
//!
//! The fourth id, `run_id`, names an EVENT and not content: two runs of the
//! same plan are two runs. It is a UUIDv7, so the id sorts by time, which is
//! what a state directory full of `runs/<run-id>/` wants.

use chrono::{DateTime, Utc};
use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::{NoContext, Timestamp, Uuid};

use crate::canonical;

/// Which contract object an id is for. The prefix is part of the id so that a
/// `plan_id` pasted where a `release_id` belongs is a sentence and not a
/// mismatch nobody can read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdKind {
    Manifest,
    Release,
    Plan,
}

impl IdKind {
    pub fn prefix(self) -> &'static str {
        match self {
            IdKind::Manifest => "manifest",
            IdKind::Release => "release",
            IdKind::Plan => "plan",
        }
    }

    /// The field that holds this id, and that is therefore not part of it.
    pub fn field(self) -> &'static str {
        match self {
            IdKind::Manifest => "manifest_id",
            IdKind::Release => "release_id",
            IdKind::Plan => "plan_id",
        }
    }

    /// Everything left out of the hash, as dotted paths into the object. See
    /// the module note for why each one is here.
    pub fn excluded(self) -> &'static [&'static str] {
        match self {
            IdKind::Manifest => &["manifest_id", "created_at", "tool", "source.repo_path"],
            // A release and a plan embed a manifest that already carries its
            // own id, so the same three fields inside it are covered by that.
            IdKind::Release => &["release_id", "created_at", "build_env"],
            IdKind::Plan => &["plan_id", "created_at"],
        }
    }
}

/// The id of a contract object: `<kind>-<sha256 of its canonical json, with
/// its own id field removed>`.
///
/// The full digest, not a prefix of one. These ids are pasted between a
/// terminal and an approval, never typed from memory, and a truncated hash is
/// a hash somebody can eventually collide on purpose.
pub fn content_id<T: Serialize>(kind: IdKind, object: &T) -> anyhow::Result<String> {
    let mut value = serde_json::to_value(object)
        .map_err(|e| anyhow::anyhow!("this object could not be written as json: {e}"))?;
    if !value.is_object() {
        anyhow::bail!("a {} id is only defined for a json object", kind.prefix());
    }
    // Absent is fine: the id is computed before it is set, and a field this
    // kind does not have yet is a field nobody has to hash.
    for path in kind.excluded() {
        remove_path(&mut value, path);
    }
    let digest = Sha256::digest(canonical::to_vec(&value));
    Ok(format!("{}-{}", kind.prefix(), hex(&digest)))
}

/// A new run's id. Takes the time rather than reading the clock, because
/// every clock in this tool is [`crate::effects::Clock`] — a run replayed in
/// a test has the timestamp the test chose.
pub fn run_id(now: DateTime<Utc>) -> Uuid {
    let seconds = now.timestamp().max(0) as u64;
    let nanos = now.timestamp_subsec_nanos();
    Uuid::new_v7(Timestamp::from_unix(NoContext, seconds, nanos))
}

/// Remove `a.b.c` from a JSON object, if it is there. Only objects are walked
/// — there is no field inside an array this needs to reach, and inventing a
/// syntax for one would be inventing a query language.
fn remove_path(value: &mut serde_json::Value, path: &str) {
    let Some((head, rest)) = path.split_once('.') else {
        if let Some(map) = value.as_object_mut() {
            map.remove(path);
        }
        return;
    };
    if let Some(inner) = value.as_object_mut().and_then(|m| m.get_mut(head)) {
        remove_path(inner, rest);
    }
}

/// The sha256 of some bytes, as lower-case hex — the same digest
/// `sha256sum` prints, so that anything this tool names can be checked by
/// hand.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// Bytes as lower-case hex.
pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn manifest_like() -> Value {
        json!({
            "manifest_id": "manifest-whatever-was-there-before",
            "created_at": "2026-09-21T10:00:00Z",
            "tool": {"name": "meister-deploy", "version": "0.1.0", "git_rev": "f83cd70"},
            "fleet": {"name": "one-box", "domain": "lab", "schema": 2},
            "hosts": {"box": {"address": "10.0.0.10"}},
            "source": {
                "repo_path": "/home/silas/git/meisterstack-lab",
                "fingerprint": "git:f83cd70:8a1c",
                "dirty": false
            }
        })
    }

    #[test]
    fn the_same_object_is_the_same_id() {
        let a = manifest_like();
        let b: Value = serde_json::from_str(&serde_json::to_string(&a).unwrap()).unwrap();
        assert_eq!(
            content_id(IdKind::Manifest, &a).unwrap(),
            content_id(IdKind::Manifest, &b).unwrap()
        );
    }

    #[test]
    fn the_id_field_is_not_part_of_the_id() {
        let mut other = manifest_like();
        other["manifest_id"] = json!("manifest-something-else-entirely");
        assert_eq!(
            content_id(IdKind::Manifest, &manifest_like()).unwrap(),
            content_id(IdKind::Manifest, &other).unwrap(),
            "otherwise the id would have to contain itself"
        );
    }

    #[test]
    fn a_changed_field_is_a_changed_id() {
        let before = content_id(IdKind::Manifest, &manifest_like()).unwrap();
        let mut after = manifest_like();
        after["hosts"]["box"]["address"] = json!("10.0.0.11");
        assert_ne!(before, content_id(IdKind::Manifest, &after).unwrap());

        // Including one nobody looks at twice: a flipped `dirty` is a
        // different manifest even when every store path is identical.
        let mut dirty = manifest_like();
        dirty["source"]["dirty"] = json!(true);
        assert_ne!(before, content_id(IdKind::Manifest, &dirty).unwrap());
    }

    #[test]
    fn a_dev_fingerprint_is_never_a_clean_one() {
        let mut clean = manifest_like();
        clean["source"]["fingerprint"] = json!("git:f83cd70:8a1c");
        let mut dev = manifest_like();
        dev["source"]["fingerprint"] = json!("dev:8a1c");
        assert_ne!(
            content_id(IdKind::Manifest, &clean).unwrap(),
            content_id(IdKind::Manifest, &dev).unwrap()
        );
    }

    #[test]
    fn key_order_in_the_input_does_not_reach_the_id() {
        let a: Value = serde_json::from_str(r#"{"a":1,"b":2,"manifest_id":"x"}"#).unwrap();
        let b: Value = serde_json::from_str(r#"{"manifest_id":"y","b":2,"a":1}"#).unwrap();
        assert_eq!(
            content_id(IdKind::Manifest, &a).unwrap(),
            content_id(IdKind::Manifest, &b).unwrap()
        );
    }

    #[test]
    fn the_time_of_a_resolve_is_not_part_of_what_it_resolved() {
        let mut later = manifest_like();
        later["created_at"] = json!("2026-09-21T14:05:00Z");
        assert_eq!(
            content_id(IdKind::Manifest, &manifest_like()).unwrap(),
            content_id(IdKind::Manifest, &later).unwrap(),
            "the same tree resolved twice is the same manifest"
        );
    }

    #[test]
    fn where_the_repository_sits_is_not_part_of_what_it_says() {
        let mut elsewhere = manifest_like();
        elsewhere["source"]["repo_path"] = json!("/build/ci/checkout-4711");
        assert_eq!(
            content_id(IdKind::Manifest, &manifest_like()).unwrap(),
            content_id(IdKind::Manifest, &elsewhere).unwrap(),
            "the same commit cloned somewhere else is the same fleet"
        );
        // And the rest of `source` still counts.
        let mut other_tree = manifest_like();
        other_tree["source"]["fingerprint"] = json!("git:0000000:1111111");
        assert_ne!(
            content_id(IdKind::Manifest, &manifest_like()).unwrap(),
            content_id(IdKind::Manifest, &other_tree).unwrap()
        );
    }

    #[test]
    fn which_build_of_the_tool_asked_is_not_part_of_the_answer() {
        let mut newer = manifest_like();
        newer["tool"]["git_rev"] = json!("aaaaaaa");
        newer["tool"]["version"] = json!("0.2.0");
        assert_eq!(
            content_id(IdKind::Manifest, &manifest_like()).unwrap(),
            content_id(IdKind::Manifest, &newer).unwrap()
        );
    }

    #[test]
    fn a_dotted_exclusion_removes_only_that_field() {
        let mut value = json!({"source": {"a": 1, "repo_path": "/x"}, "repo_path": "/y"});
        remove_path(&mut value, "source.repo_path");
        assert_eq!(value, json!({"source": {"a": 1}, "repo_path": "/y"}));
        // A path that is not there is not an error.
        remove_path(&mut value, "source.nothing.here");
        remove_path(&mut value, "nothing");
        assert_eq!(value, json!({"source": {"a": 1}, "repo_path": "/y"}));
    }

    #[test]
    fn the_kind_is_in_the_id_and_the_digest_is_whole() {
        let id = content_id(IdKind::Plan, &json!({"plan_id": "", "a": 1})).unwrap();
        assert!(id.starts_with("plan-"), "{id}");
        assert_eq!(id.len(), "plan-".len() + 64, "a whole sha256, not a prefix");
        assert!(id[5..].chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn two_kinds_of_the_same_bytes_are_two_ids() {
        let object = json!({"a": 1});
        assert_ne!(
            content_id(IdKind::Release, &object).unwrap(),
            content_id(IdKind::Plan, &object).unwrap()
        );
    }

    #[test]
    fn only_an_object_has_a_content_id() {
        let err = content_id(IdKind::Manifest, &json!([1, 2, 3]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("json object"), "{err}");
    }

    #[test]
    fn a_digest_is_the_one_sha256_everybody_elses_tool_computes() {
        // `printf '{}' | sha256sum` — so that an operator can check an id by
        // hand, which is the only reason to canonicalize at all.
        let id = content_id(IdKind::Manifest, &json!({})).unwrap();
        assert_eq!(
            id,
            "manifest-44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
        );
    }

    #[test]
    fn a_digest_is_the_one_sha256sum_prints() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn a_run_id_sorts_by_the_time_it_was_given() {
        let early = DateTime::parse_from_rfc3339("2026-09-21T10:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let late = DateTime::parse_from_rfc3339("2026-09-21T10:00:01Z")
            .unwrap()
            .with_timezone(&Utc);
        let a = run_id(early);
        let b = run_id(late);
        assert_eq!(a.get_version_num(), 7);
        assert!(a.to_string() < b.to_string(), "{a} should sort before {b}");
        assert_ne!(run_id(early), run_id(early), "two runs are two runs");
    }
}

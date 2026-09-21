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
    let map = value.as_object_mut().ok_or_else(|| {
        anyhow::anyhow!("a {} id is only defined for a json object", kind.prefix())
    })?;
    // Absent is fine: the id is computed before it is set.
    map.remove(kind.field());
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

fn hex(bytes: &[u8]) -> String {
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
            "fleet": {"name": "one-box", "domain": "lab", "schema": 2},
            "hosts": {"box": {"address": "10.0.0.10"}},
            "source": {"fingerprint": "git:f83cd70:8a1c", "dirty": false}
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

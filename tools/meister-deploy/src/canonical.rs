// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! One JSON object, one byte string — whatever the map underneath happens to
//! be.
//!
//! Every id in this tool is a hash over a contract object, so two runs that
//! mean the same thing have to produce the same bytes. `serde_json` cannot be
//! trusted with that on its own: its `preserve_order` feature swaps the
//! `BTreeMap` behind `Value::Object` for an `IndexMap`, key order becomes
//! insertion order, and feature unification means any crate anywhere in the
//! workspace can turn it on without this one noticing. An id that changes
//! because somebody added a dependency is an id nobody can compare against
//! yesterday's manifest.
//!
//! So the structure is written here — sorted keys, no whitespace — and only
//! the two leaf cases where `serde_json` has no map to reorder are delegated
//! to it: string escaping and number formatting.
//!
//! Contract objects carry no floating point numbers. Integers and strings
//! have one spelling; `0.1 + 0.2` does not, and an id over one would depend
//! on which machine computed the field.

use serde_json::Value;

/// The canonical bytes of a value: object keys sorted by their UTF-8 bytes,
/// arrays in their own order, nothing between the tokens.
pub fn to_vec(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    write(value, &mut out);
    out
}

/// The same, as text — for an error message or a test that wants to read it.
pub fn to_string(value: &Value) -> String {
    // The writer only ever emits what serde_json produced plus ASCII
    // punctuation, so this cannot fail.
    String::from_utf8(to_vec(value)).expect("canonical json is utf-8 by construction")
}

fn write(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        // One leaf each: `Number` prints itself (integers exactly, floats via
        // the shortest round-tripping form) and `String` escapes itself. No
        // map is involved in either, so no ordering can differ.
        Value::Number(n) => out.extend_from_slice(n.to_string().as_bytes()),
        Value::String(s) => out.extend_from_slice(
            serde_json::to_string(s)
                .expect("a string always serializes")
                .as_bytes(),
        ),
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write(item, out);
            }
            out.push(b']');
        }
        Value::Object(map) => {
            // Sorted here rather than trusted from the map. `sort_unstable`
            // is fine: JSON object keys are unique, so there are no ties.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable();
            out.push(b'{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write(&Value::String((*key).clone()), out);
                out.push(b':');
                write(&map[key.as_str()], out);
            }
            out.push(b'}');
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn two_differently_written_objects_are_the_same_bytes() {
        let a: Value = serde_json::from_str(r#"{"b":1,"a":{"z":[1,2],"y":"x"}}"#).unwrap();
        let b: Value = serde_json::from_str(r#"{"a":{"y":"x","z":[1,2]},"b":1}"#).unwrap();
        assert_eq!(to_vec(&a), to_vec(&b));
        assert_eq!(to_string(&a), r#"{"a":{"y":"x","z":[1,2]},"b":1}"#);
    }

    #[test]
    fn nesting_is_sorted_all_the_way_down() {
        let v = json!({
            "hosts": {"n2": {"b": 1, "a": 2}, "box": {"z": 0, "a": 0}},
            "fleet": {"name": "one-box"}
        });
        assert_eq!(
            to_string(&v),
            r#"{"fleet":{"name":"one-box"},"hosts":{"box":{"a":0,"z":0},"n2":{"a":2,"b":1}}}"#
        );
    }

    #[test]
    fn array_order_is_data_and_is_kept() {
        let v = json!({"members": ["c", "a", "b"]});
        assert_eq!(to_string(&v), r#"{"members":["c","a","b"]}"#);
    }

    #[test]
    fn strings_are_escaped_the_one_way_json_escapes_them() {
        let v = json!({"reason": "it said \"no\"\n\tand left", "path": "/a\\b"});
        assert_eq!(
            to_string(&v),
            r#"{"path":"/a\\b","reason":"it said \"no\"\n\tand left"}"#
        );
    }

    #[test]
    fn unicode_keys_sort_by_their_bytes_and_stay_stable() {
        let v: Value = serde_json::from_str(r#"{"ü":1,"z":2,"a":3}"#).unwrap();
        // "a" < "z" < "ü" as UTF-8 bytes; the point is that it is the same
        // answer on every machine, not that it matches any locale.
        assert_eq!(to_string(&v), "{\"a\":3,\"z\":2,\"ü\":1}");
    }

    #[test]
    fn the_empty_cases_have_one_spelling_too() {
        assert_eq!(to_string(&json!({})), "{}");
        assert_eq!(to_string(&json!([])), "[]");
        assert_eq!(to_string(&json!(null)), "null");
        assert_eq!(
            to_string(&json!({"a": null, "b": []})),
            r#"{"a":null,"b":[]}"#
        );
    }

    #[test]
    fn integers_keep_their_exact_spelling() {
        // Past 2^53 and past i64: an id over a disk size has to survive a
        // round trip through json, and serde_json keeps these exactly.
        let v: Value =
            serde_json::from_str(r#"{"size":9007199254740993,"big":18446744073709551615}"#)
                .unwrap();
        assert_eq!(
            to_string(&v),
            r#"{"big":18446744073709551615,"size":9007199254740993}"#
        );
    }

    #[test]
    fn a_float_is_why_a_contract_object_carries_none() {
        // `-0` is not an integer to serde_json; it comes back as the float
        // -0.0 and prints as one. Nothing is wrong with the canonicalizer
        // here — this is the reason the contracts have no float fields.
        let v: Value = serde_json::from_str(r#"{"n":-0}"#).unwrap();
        assert_eq!(to_string(&v), r#"{"n":-0.0}"#);
    }
}

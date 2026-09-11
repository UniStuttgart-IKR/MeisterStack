// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! `/schemas`: the shape of every resource this tier serves, generated from
//! the types themselves. Moved out of `rest.rs` unchanged.

use super::*;

// --- schemas ----------------------------------------------------------------

/// Where a client asks what an object of this API LOOKS like.
///
/// The discovery document says which resources exist and what may be done to
/// them; it says nothing about fields, and that gap is why every client so far
/// had to be handed a written reference and a human to read it. This is the
/// other half: one JSON Schema per resource, derived from the very types serde
/// deserialises, plus the mutability table the update handler enforces.
///
/// Under `/apis/meister.io/v1/` so `classify` sees it as an API path with no
/// object under it and lets it past ungated, exactly as it lets discovery
/// past — the shape of an object is not a secret, and a client needs it
/// before it has a credential to ask with.
pub const SCHEMAS_PATH: &str = "/apis/meister.io/v1/schemas";

/// The schema of one resource, as `/schemas` publishes it.
///
/// Generic over the object rather than taking a `Value`, so that the call site
/// reads `schema_of::<Vm>()` and cannot name a type this endpoint does not
/// actually serve.
pub fn schema_of<T: schemars::JsonSchema>() -> serde_json::Value {
    serde_json::to_value(schemars::schema_for!(T)).unwrap_or(serde_json::Value::Null)
}

/// The whole document, built once when the router is.
pub fn schema_document(resources: &'static [ApiResource]) -> serde_json::Value {
    let mut schemas = serde_json::Map::new();
    for resource in resources {
        let Some(build) = resource.schema else {
            continue;
        };
        let mutability: Vec<serde_json::Value> = resource
            .owned_fields()
            .iter()
            .map(|owned| {
                let mut row = serde_json::json!({
                    "field": owned.path,
                    "mutability": owned.kind.as_str(),
                    // The server's own sentence, so a form can show the
                    // reason it would have shown as a 422 — before somebody
                    // typed into a field they were never allowed to change.
                    "because": format!("{} {}", owned.path, owned.because),
                });
                if let Some(note) = owned.note {
                    // Only where there is one: an absent key is "nothing is
                    // coming", which is what almost every row means and what
                    // every row meant before this key existed.
                    row["note"] = serde_json::Value::String(note.to_string());
                }
                row
            })
            .collect();
        schemas.insert(
            resource.kind.to_string(),
            serde_json::json!({
                "resource": resource.name,
                "schema": build(),
                "mutability": mutability,
            }),
        );
    }
    serde_json::json!({
        "apiVersion": API_VERSION,
        "kind": "SchemaList",
        "schemas": serde_json::Value::Object(schemas),
    })
}

pub(super) async fn api_schemas(
    State(doc): State<Arc<serde_json::Value>>,
) -> Json<serde_json::Value> {
    Json((*doc).clone())
}

/// Every path a mutability table names has to be a field the schema
/// really has.
///
/// This is what holds the two statements together, and it is the whole
/// reason the table travels beside the schema rather than in prose. The
/// table is hand-written; the schema is derived from the type serde
/// deserialises. Rename `sizeGib` in `VolumeSpec` and this fails —
/// whereas a sentence in a document would have gone on being wrong
/// quietly, which is exactly what happened to `spec.size` in the brief
/// this came from.
pub fn assert_tables_match_schemas(resources: &'static [ApiResource]) {
    for resource in resources {
        let Some(build) = resource.schema else {
            assert!(
                resource.owned_fields().is_empty(),
                "{} names owned fields but publishes no schema to hold them to",
                resource.kind
            );
            continue;
        };
        let schema = build();
        for owned in resource.owned_fields() {
            assert!(
                schema_has_field(&schema, owned.path),
                "{}: the mutability table names {:?}, which is not a field of its schema",
                resource.kind,
                owned.path
            );
        }
    }
}

/// Walk a dotted path through a JSON Schema's `properties`.
///
/// Deliberately only `properties`: every path any table names today is a
/// plain field, and a walker that also followed `$ref`, `oneOf` and
/// `additionalProperties` would be a walker that finds something for
/// almost any string — which would make the assertion above pass for a
/// typo. `$ref` IS followed, because schemars puts every named struct
/// behind one and `spec` is always a `$ref`.
pub fn schema_has_field(schema: &serde_json::Value, path: &str) -> bool {
    let root = schema;
    let mut here = schema;
    for segment in path.split('.') {
        here = match resolve(root, here)
            .get("properties")
            .and_then(|p| p.get(segment))
        {
            Some(next) => next,
            None => return false,
        };
    }
    true
}

/// One `$ref` hop into `$defs`, which is where schemars keeps the structs.
pub(super) fn resolve<'a>(
    root: &'a serde_json::Value,
    node: &'a serde_json::Value,
) -> &'a serde_json::Value {
    let Some(reference) = node.get("$ref").and_then(|r| r.as_str()) else {
        return node;
    };
    reference
        .strip_prefix("#/$defs/")
        .and_then(|name| root.get("$defs")?.get(name))
        .unwrap_or(node)
}

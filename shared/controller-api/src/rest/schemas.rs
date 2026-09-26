// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! JSON schemas and field mutability for resources served by a tier.

use super::*;

// --- schemas ----------------------------------------------------------------

/// Public endpoint for derived resource JSON schemas and enforced
/// mutability tables. Complements resource/verb discovery.
pub const SCHEMAS_PATH: &str = "/apis/meister.io/v1/schemas";

/// Generate the complete JSON Schema for a resource type.
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

/// Assert that every hand-written mutability path exists in its derived
/// resource schema, so field renames cannot silently leave stale policy.
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

/// Find a dotted field through properties and local references.
/// Do not treat unions or additionalProperties as evidence that a named field
/// exists; mutability tables require explicit schema fields.
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

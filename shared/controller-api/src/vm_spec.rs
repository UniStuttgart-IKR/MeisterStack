// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! `spec.vm`, refused where the client can still read the refusal.
//!
//! Before this, both REST edges took `spec.vm` as an opaque `Value` and
//! answered 201. The node — three tiers down and some seconds later —
//! deserialised it into `agent_api::spec::NewVmSpec`, said `missing field
//! "boot"` or `unknown field "base_image"`, and put that sentence into
//! `status.message`, where no caller of the POST was listening. A declarative
//! client had already written state and told its user the machine existed.
//!
//! There is no second schema here and there must not be: the tier boundary is
//! right, and this edge still knows nothing about sizing, images on disk or
//! what a driver is. What it does is the SAME deserialisation, at the front,
//! and it hands serde's own sentence back as a 422 with `details.field`.
//!
//! Beside it, the one structural rule about the document that needs no node
//! to be true: a VM needs a boot disk. `vcpus >= 1` has been checked at the
//! edge since api-honesty for exactly the same reason.

use agent_api::spec::{BootSourceSpec, CloudInit, NewDevice, NewNic, NewVmSpec, NewVolume};

use crate::rest::{ApiError, invalid_field};

/// Where a refusal about this document points when it cannot point closer.
pub const ROOT: &str = "spec.vm";

/// Deserialise `spec.vm` into the node's own create document, or say why not.
///
/// Called from the POST and the PUT of both tiers. `Ok` means the node will
/// take this document — not that it will succeed, which is a question about a
/// machine and not about a document.
pub fn check(vm: &serde_json::Value) -> Result<(), ApiError> {
    // The two numbers first, off the raw JSON, because serde would answer
    // `-1` with "invalid type: integer" and name no field at all — and this
    // refusal has said which field and why since api-honesty. It was made at
    // the cloud edge and nowhere else; both tiers make it now, because the
    // cluster edge is reachable on its own.
    sizes(vm)?;
    let spec: NewVmSpec = match serde_json::from_value(vm.clone()) {
        Ok(spec) => spec,
        Err(e) => return Err(narrow(vm).unwrap_or_else(|| point(ROOT, &e.to_string()))),
    };
    // Structural, and the last refusal the node makes that this edge could
    // not: a document with no disk describes a machine that cannot boot, and
    // that is a property of the document rather than of a node.
    if spec.volumes.is_empty() {
        return Err(invalid_field(
            "spec.vm.volumes",
            "a vm needs at least one volume as boot disk",
        ));
    }
    Ok(())
}

/// The line between "not a VM" and "no room today", and it is the line this
/// control plane refuses to move: a machine with no cpu is malformed, and a
/// machine nothing has room for is `Pending` with a reason.
///
/// Off the raw document rather than off the parsed one, so that it can also
/// answer a value that is not a number of anything.
fn sizes(vm: &serde_json::Value) -> Result<(), ApiError> {
    for field in ["vcpus", "memory_mib"] {
        let Some(value) = vm.get(field) else { continue };
        if value.as_u64().is_none_or(|n| n < 1) {
            return Err(invalid_field(
                &format!("{ROOT}.{field}"),
                format!("{ROOT}.{field} must be at least 1; {value} is not a vm"),
            ));
        }
    }
    Ok(())
}

/// The refusal, pointed at the part of the document that really makes it.
///
/// `serde_json::from_value` keeps no path, so its sentence names a field and
/// not a place — and `kind` is a field of `boot` AND a typo somebody wrote in
/// a volume. So the document is taken apart instead: every nested part is
/// offered to its own type, and the first one that refuses owns the refusal
/// and lends it its own path. A `None` means every part parses on its own and
/// the fault is at the top level, where the whole-document message is exact.
fn narrow(vm: &serde_json::Value) -> Option<ApiError> {
    if let Some(boot) = vm.get("boot")
        && let Err(e) = serde_json::from_value::<BootSourceSpec>(boot.clone())
    {
        return Some(point(&format!("{ROOT}.boot"), &e.to_string()));
    }
    if let Some(seed) = vm.get("cloud_init").filter(|c| !c.is_null())
        && let Err(e) = serde_json::from_value::<CloudInit>(seed.clone())
    {
        return Some(point(&format!("{ROOT}.cloud_init"), &e.to_string()));
    }
    for (i, entry) in entries(vm, "volumes") {
        if let Err(e) = serde_json::from_value::<NewVolume>(entry.clone()) {
            return Some(point(&format!("{ROOT}.volumes[{i}]"), &e.to_string()));
        }
    }
    for (i, entry) in entries(vm, "nics") {
        if let Err(e) = serde_json::from_value::<NewNic>(entry.clone()) {
            return Some(point(&format!("{ROOT}.nics[{i}]"), &e.to_string()));
        }
    }
    for (i, entry) in entries(vm, "devices") {
        if let Err(e) = serde_json::from_value::<NewDevice>(entry.clone()) {
            return Some(point(&format!("{ROOT}.devices[{i}]"), &e.to_string()));
        }
    }
    None
}

fn entries<'a>(
    vm: &'a serde_json::Value,
    field: &str,
) -> impl Iterator<Item = (usize, &'a serde_json::Value)> {
    vm.get(field)
        .and_then(|v| v.as_array())
        .map(Vec::as_slice)
        .unwrap_or(&[])
        .iter()
        .enumerate()
}

/// The 422, with `details.field` one segment deeper where serde named a field
/// of the object it was given.
///
/// Only the two messages that really name a field of THIS object are followed
/// — `missing field` and `unknown field`. `unknown variant` and `invalid
/// type` also carry a backtick, and what is between it is a value rather than
/// a field: a path built out of those would point at something the client
/// cannot find in its own request, which is worse than no path.
fn point(prefix: &str, message: &str) -> ApiError {
    let named = message.starts_with("missing field") || message.starts_with("unknown field");
    match quoted(message).filter(|_| named) {
        Some(field) => invalid_field(&format!("{prefix}.{field}"), message),
        None => invalid_field(prefix, message),
    }
}

/// The name between the first pair of backticks.
fn quoted(message: &str) -> Option<&str> {
    let (name, _) = message.split_once('`')?.1.split_once('`')?;
    (!name.is_empty()).then_some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The smallest document the node takes, for the tests that spoil one
    /// field of it.
    fn valid() -> serde_json::Value {
        serde_json::json!({
            "vcpus": 1,
            "memory_mib": 512,
            "boot": {"kind": "firmware", "firmware": "fw"},
            "volumes": [{"size_bytes": 1}]
        })
    }

    fn refusal(vm: serde_json::Value) -> (String, String) {
        let err = check(&vm).expect_err("refused");
        (
            err.field().unwrap_or_default().to_string(),
            err.message().to_string(),
        )
    }

    /// The three sentences the UI collected while building its example world.
    /// Each of them was a 201 followed by a `status.message`; each of them is
    /// now the answer to the POST itself, with a field path.
    #[test]
    fn the_refusals_the_node_used_to_make_are_made_here() {
        let (field, message) = refusal(serde_json::json!({
            "vcpus": 1, "memory_mib": 512,
            "volumes": [{"size_bytes": 1}]
        }));
        assert_eq!(field, "spec.vm.boot");
        assert!(message.contains("missing field `boot`"), "{message}");

        let (field, message) = refusal(serde_json::json!({
            "vcpus": 1, "memory_mib": 512,
            "boot": {"kind": "firmware", "firmware": "fw"},
            "base_image": "debian-13.raw",
            "volumes": [{"size_bytes": 1}]
        }));
        assert_eq!(field, "spec.vm.base_image");
        assert!(message.contains("unknown field `base_image`"), "{message}");

        let (field, message) = refusal(serde_json::json!({
            "vcpus": 1, "memory_mib": 512,
            "boot": {"kind": "firmware", "firmware": "fw"},
            "volumes": [{"kind": "disk", "size_bytes": 1}]
        }));
        assert_eq!(field, "spec.vm.volumes[0].kind");
        assert!(message.contains("unknown field `kind`"), "{message}");
    }

    /// The fourth one, and the only rule here that serde cannot state: a
    /// document with no disk is a machine that cannot boot.
    #[test]
    fn a_vm_needs_a_boot_disk() {
        let (field, message) = refusal(serde_json::json!({
            "vcpus": 1, "memory_mib": 512,
            "boot": {"kind": "firmware", "firmware": "fw"}
        }));
        assert_eq!(field, "spec.vm.volumes");
        assert_eq!(message, "a vm needs at least one volume as boot disk");
    }

    /// A device without its partition, to prove the path recovery does not
    /// stop at the top level for the fields that nest.
    #[test]
    fn a_nested_unknown_field_is_pointed_at_where_it_sits() {
        let (field, _) = refusal(serde_json::json!({
            "vcpus": 1, "memory_mib": 512,
            "boot": {"kind": "firmware", "firmware": "fw"},
            "volumes": [{"size_bytes": 1}],
            "nics": [{"bridge": "br0"}, {"bridge": "br0", "readonly": true}]
        }));
        assert_eq!(field, "spec.vm.nics[1].readonly");
    }

    /// The line between "not a VM" and "no room today", and it is the line
    /// this control plane refuses to move. Moved here from the cloud edge,
    /// which was the only tier making it.
    #[test]
    fn a_vm_with_no_cpu_is_refused_and_a_vm_that_is_merely_huge_is_not() {
        // Not a VM. Both of these answered 201 before, bound, burned a
        // scheduling slot and came back Failed from the agent.
        for (field, value) in [
            ("vcpus", serde_json::json!(0)),
            ("vcpus", serde_json::json!(-1)),
            ("memory_mib", serde_json::json!(0)),
            ("memory_mib", serde_json::json!(-1)),
        ] {
            let mut doc = valid();
            doc[field] = value.clone();
            let (got, message) = refusal(doc);
            assert_eq!(got, format!("spec.vm.{field}"));
            assert!(
                message.starts_with(&format!("spec.vm.{field} ")),
                "{message}"
            );
        }

        // A sizing question, and this tier does not answer sizing questions:
        // it is the scheduler's, against real capacity, and a VM nothing has
        // room for today is `Pending` with a reason rather than a 422.
        let mut huge = valid();
        huge["vcpus"] = serde_json::json!(100_000);
        huge["memory_mib"] = serde_json::json!(1_000_000_000u64);
        check(&huge).expect("huge is not malformed");

        // And a value that is not a number at all is not a number of cpus.
        for value in [
            serde_json::json!("two"),
            serde_json::json!(1.5),
            serde_json::json!(null),
            serde_json::json!([2]),
        ] {
            let mut doc = valid();
            doc["vcpus"] = value.clone();
            assert!(check(&doc).is_err(), "{value} is not a cpu count");
        }

        // A field the client did not name is a field the DOCUMENT names, and
        // that is what changed here: `{}` used to be accepted by this edge
        // and refused by the node a minute later.
        let (got, message) = refusal(serde_json::json!({}));
        assert_eq!(got, "spec.vm.vcpus");
        assert!(message.contains("missing field `vcpus`"), "{message}");
    }

    /// And the document the CLI guide tells everybody to write still passes.
    #[test]
    fn a_valid_document_is_accepted() {
        check(&serde_json::json!({
            "vcpus": 2,
            "memory_mib": 2048,
            "boot": {"kind": "direct_kernel", "kernel": "vmlinux", "cmdline": "console=ttyS0"},
            "volumes": [{"base_image": "debian-13.raw", "size_bytes": 10737418240u64}],
            "nics": [{"bridge": "br0"}]
        }))
        .expect("a spec the node takes");
    }
}

// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Validate `spec.vm` at the REST edge using shared agent field types.
//!
//! The edge accepts cloud-init secret references, which controllers must resolve
//! before delivery to the agent. Local image, device and driver checks remain
//! on the agent.

use agent_api::spec::{BootSourceSpec, Desired, NewDevice, NewNic, NewVolume};

use crate::rest::{ApiError, invalid_field};

/// Where a refusal about this document points when it cannot point closer.
pub const ROOT: &str = "spec.vm";

/// The agent create shape with a cloud-init variant for unresolved secret
/// references. Controllers resolve `user_data_from` before node delivery; the
/// agent still requires literal `user_data`. Keep common fields aligned with
/// `agent_api::spec::NewVmSpec`.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CloudVmSpec {
    #[allow(dead_code)] // read via `sizes`, off the raw document
    vcpus: u32,
    #[allow(dead_code)]
    memory_mib: u64,
    #[allow(dead_code)]
    boot: BootSourceSpec,
    #[serde(default)]
    #[allow(dead_code)]
    desired: Desired,
    #[serde(default)]
    volumes: Vec<NewVolume>,
    #[serde(default)]
    #[allow(dead_code)]
    nics: Vec<NewNic>,
    #[serde(default)]
    #[allow(dead_code)]
    devices: Vec<NewDevice>,
    #[serde(default)]
    cloud_init: Option<CloudInitAtEdge>,
}

/// `agent_api::spec::CloudInit`, with `user_data` optional and a second way
/// in beside it. See `CloudVmSpec` for why this is not that type.
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CloudInitAtEdge {
    #[serde(default)]
    user_data: Option<String>,
    #[serde(default)]
    user_data_from: Option<UserDataFrom>,
    #[serde(default)]
    #[allow(dead_code)]
    meta_data: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    network_config: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    local_hostname: Option<String>,
}

/// Secret and key reference shape, also read from raw JSON by VmSpec.
/// Keep both representations structurally aligned.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct UserDataFrom {
    #[allow(dead_code)]
    secret: String,
    #[allow(dead_code)]
    key: String,
}

/// Validate the cloud VM document using shared agent field types.
/// Secret resolution and node-specific feasibility remain separate.
pub fn check(vm: &serde_json::Value) -> Result<(), ApiError> {
    // Check numeric bounds first so invalid values receive a precise field path
    // instead of an unlocated serde type error.
    sizes(vm)?;
    let spec: CloudVmSpec = match serde_json::from_value(vm.clone()) {
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
    // Require a cloud-init source. This rejects neither being supplied;
    // VmSpec.user_data_said_twice separately rejects both literal and reference.
    if let Some(seed) = &spec.cloud_init {
        let literal = seed.user_data.as_deref().is_some_and(|s| !s.is_empty());
        if !literal && seed.user_data_from.is_none() {
            return Err(invalid_field(
                "spec.vm.cloud_init",
                "cloud_init needs a starting point: user_data or user_data_from",
            ));
        }
    }
    Ok(())
}

/// Reject present CPU and memory values that are not positive integers.
/// Valid demand exceeding available capacity is a placement issue instead.
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

/// Reparse nested fields to locate a serde failure within the VM document.
/// If each part parses, return None and use the top-level deserialization error.
fn narrow(vm: &serde_json::Value) -> Option<ApiError> {
    if let Some(boot) = vm.get("boot")
        && let Err(e) = serde_json::from_value::<BootSourceSpec>(boot.clone())
    {
        return Some(point(&format!("{ROOT}.boot"), &e.to_string()));
    }
    if let Some(seed) = vm.get("cloud_init").filter(|c| !c.is_null())
        && let Err(e) = serde_json::from_value::<CloudInitAtEdge>(seed.clone())
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

/// Extend the error path only for serde missing-field and unknown-field messages.
/// Quoted variants and invalid values are not field names.
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

    /// Accept unresolved cloud-init secret references for downstream resolution.
    #[test]
    fn a_cloud_init_secret_reference_is_accepted() {
        let mut doc = valid();
        doc["cloud_init"] = serde_json::json!({
            "user_data_from": { "secret": "db", "key": "password" }
        });
        check(&doc).expect("a reference is not an unknown field");
    }

    /// Cloud-init requires a source even though literal user_data is optional.
    /// Supplying both sources is checked separately.
    #[test]
    fn a_cloud_init_naming_no_starting_point_is_refused() {
        let mut doc = valid();
        doc["cloud_init"] = serde_json::json!({});
        let (field, message) = refusal(doc);
        assert_eq!(field, "spec.vm.cloud_init");
        assert!(message.contains("needs a starting point"), "{message}");

        // Absent entirely is untouched: no seed at all is legal and has
        // nothing to name a starting point for.
        assert!(
            check(&valid()).is_ok(),
            "no cloud_init at all is not a refusal"
        );
    }
}

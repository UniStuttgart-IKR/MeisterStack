// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Collect startup machine facts for migration admission. Host files are read
//! best effort; missing fields remain empty. The controller defines how unknown
//! values affect compatibility, including restrictions for nested hosts.

use std::path::Path;

/// Snapshot this node's host and VMM profile at agent startup.
pub fn profile(
    physical_host: Option<&str>,
    cpu_profile: &str,
    hypervisor: &str,
) -> proto::MachineProfile {
    let cpuinfo = read("/proc/cpuinfo");
    let flags = field(&cpuinfo, "flags");
    proto::MachineProfile {
        cpu_vendor: field(&cpuinfo, "vendor_id"),
        cpu_model: field(&cpuinfo, "model name"),
        // Canonical ordering makes equivalent CPU-flag sets compare equal.
        cpu_flags: sorted(&flags),
        // The `hypervisor` flag, which is the CPUID bit every hypervisor sets
        // and the only answer to "am I a guest" that needs nothing but a file.
        nested: flags.split_whitespace().any(|f| f == "hypervisor"),
        hypervisor: dmi("sys_vendor"),
        cpu_profile: cpu_profile.to_string(),
        hypervisor_version: hypervisor.to_string(),
        kernel: read("/proc/sys/kernel/osrelease").trim().to_string(),
        host: match physical_host {
            // An explicit host identity overrides DMI, which may be unhelpful for nested nodes.
            Some(named) if !named.is_empty() => named.to_string(),
            _ => dmi("board_serial"),
        },
    }
}

/// Read the first matching field from cpuinfo. This does not intersect flags
/// across heterogeneous cores. Missing fields yield an empty string.
fn field(text: &str, key: &str) -> String {
    text.lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.trim() == key)
        .map(|(_, value)| value.trim().to_string())
        .unwrap_or_default()
}

/// The words of `flags`, sorted and joined by one space.
fn sorted(flags: &str) -> String {
    let mut words: Vec<&str> = flags.split_whitespace().collect();
    words.sort_unstable();
    words.join(" ")
}

/// Read a DMI field best effort. physical_host can override unreliable serials.
fn dmi(field: &str) -> String {
    read(&format!("/sys/class/dmi/id/{field}"))
        .trim()
        .to_string()
}

/// A file, or an empty string. Nothing here is worth failing a start-up over.
fn read(path: &str) -> String {
    std::fs::read_to_string(Path::new(path)).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Missing fields remain empty rather than inheriting unrelated values.
    #[test]
    fn a_field_that_is_not_there_is_an_empty_answer_and_never_a_wrong_one() {
        let cpuinfo = "processor\t: 0\n\
                       vendor_id\t: GenuineIntel\n\
                       model name\t: 13th Gen Intel(R) Core(TM) i7-1360P\n\
                       flags\t\t: fpu vme hypervisor lm\n\
                       processor\t: 1\n\
                       vendor_id\t: GenuineIntel\n";
        assert_eq!(field(cpuinfo, "vendor_id"), "GenuineIntel");
        assert_eq!(
            field(cpuinfo, "model name"),
            "13th Gen Intel(R) Core(TM) i7-1360P",
            "the model name keeps its spaces and its brackets: it is what an \
             operator reads in the refusal"
        );
        // A key nothing answers to. Empty, and empty is "did not say" — which
        // is what stops a node that could read nothing from refusing every
        // migration on the fleet.
        assert_eq!(field(cpuinfo, "microcode"), "");
        assert_eq!(field("", "vendor_id"), "");

        // Sort CPU flags for order-independent profile comparison.
        assert_eq!(sorted("lm fpu hypervisor vme"), "fpu hypervisor lm vme");
        assert_eq!(sorted(""), "");
    }

    /// Read the local machine profile and preserve caller-supplied fields.
    /// Check nested status against host CPU flags without assuming either value.
    #[test]
    fn this_machine_answers_for_itself() {
        let p = profile(Some("palma"), "Host", "cloud-hypervisor v53.0");
        assert_eq!(p.host, "palma", "what an operator wrote wins");
        assert_eq!(p.cpu_profile, "Host");
        assert_eq!(p.hypervisor_version, "cloud-hypervisor v53.0");
        assert!(!p.kernel.is_empty(), "every linux has an osrelease");
        assert!(!p.cpu_vendor.is_empty(), "and a vendor_id");
        assert_eq!(
            p.nested,
            p.cpu_flags.split_whitespace().any(|f| f == "hypervisor"),
            "nested is the hypervisor flag and nothing else"
        );

        // No key: the platform is asked instead, and on most machines it says
        // nothing. Either way it is a string and never a failure.
        let unnamed = profile(None, "Host", "");
        assert_eq!(unnamed.cpu_vendor, p.cpu_vendor, "the same machine");
        assert_eq!(unnamed.hypervisor_version, "");

        // An empty physical-host override is treated as absent, not a shared host identity.
        assert_eq!(profile(Some(""), "Host", "").host, unnamed.host);
    }
    /// Pin machine-profile protobuf field numbers and verify wire round trips.
    #[test]
    fn the_profile_travels_as_itself() {
        use prost::Message;
        let said = proto::MachineProfile {
            cpu_vendor: "GenuineIntel".into(),
            cpu_model: "Intel(R) Xeon(R) Gold 6248R".into(),
            cpu_flags: "fpu lm vmx".into(),
            nested: true,
            hypervisor: "KVM".into(),
            cpu_profile: "Host".into(),
            hypervisor_version: "cloud-hypervisor v53.0".into(),
            kernel: "6.12.0".into(),
            host: "palma".into(),
        };
        let hello = proto::Hello {
            node_id: "agent-1".into(),
            agent_version: "0.1.0".into(),
            drivers: Vec::new(),
            machine: Some(said.clone()),
        };
        let back = proto::Hello::decode(hello.encode_to_vec().as_slice()).expect("it decodes");
        assert_eq!(back.machine.as_ref(), Some(&said));

        // Older agents may omit the machine profile.
        let old = proto::Hello {
            machine: None,
            ..hello
        };
        let back = proto::Hello::decode(old.encode_to_vec().as_slice()).expect("it decodes");
        assert!(back.machine.is_none());
    }
}

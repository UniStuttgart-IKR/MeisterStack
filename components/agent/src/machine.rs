// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! What a guest's machine state would be restored INTO on this node.
//!
//! One reading of `/proc` and `/sys`, once at start-up, for the one question
//! nobody could ask before a stream was already open: **can this guest's
//! saved state be restored over there?**
//!
//! A live migration does not move a program, it moves a MACHINE STATE — vCPU
//! registers, MSRs, the nested-virtualisation state. cloud-hypervisor v53
//! checks the CPUID before the transfer ("No CPU incompatibility detected")
//! and does not check the rest, so a mismatch arrives two milliseconds after
//! the vCPUs are made, as one line in a log file the control plane never
//! reads. The lab spent two nights finding that line (D-X1); the answer is
//! that nested KVM state does not cross a physical host.
//!
//! So the node says what it is, once, and the tier that chooses a destination
//! compares two of these — `controller_api::live_migration_refusal` — before
//! it opens anything. A refusal costs nothing: the guest keeps running and a
//! drain moves it by reboot.
//!
//! ## Nothing here fails
//!
//! Every reader answers with a string, and an unreadable file answers with an
//! empty one. That is deliberate and it is the whole safety rule of the
//! feature: an empty field is "did not say", never "differs", and the
//! comparison one tier up refuses only on two values that are both present.
//! An agent that could read none of this migrates exactly as it did before.

use std::path::Path;

/// This machine, as far as a saved guest state is concerned.
///
/// Read once, because none of it changes while an agent runs: a CPU does not
/// grow flags, a kernel does not renumber itself, and a VM does not move
/// between physical hosts without the guest inside it stopping first.
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
        // Sorted, because `/proc/cpuinfo` does not promise an order and two
        // nodes that offer the same set must produce the same string — a
        // comparison that tripped over the order would refuse a migration
        // between two identical machines.
        cpu_flags: sorted(&flags),
        // The `hypervisor` flag, which is the CPUID bit every hypervisor sets
        // and the only answer to "am I a guest" that needs nothing but a file.
        nested: flags.split_whitespace().any(|f| f == "hypervisor"),
        hypervisor: dmi("sys_vendor"),
        cpu_profile: cpu_profile.to_string(),
        hypervisor_version: hypervisor.to_string(),
        kernel: read("/proc/sys/kernel/osrelease").trim().to_string(),
        host: match physical_host {
            // What an operator wrote wins over what the platform says: on a
            // nested guest the platform says nothing useful, and the whole
            // reason the key exists is that somebody outside can see what the
            // machine cannot.
            Some(named) if !named.is_empty() => named.to_string(),
            _ => dmi("board_serial"),
        },
    }
}

/// One `key : value` line out of a `/proc/cpuinfo`-shaped file.
///
/// The FIRST one, which is core 0's: every core of a machine answers the same
/// vendor, model and flags, and reading all of them would be forty identical
/// strings. Empty when the key is not there, which is also what a file that
/// could not be read gives.
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

/// One field of the platform's own description of itself.
///
/// `/sys/class/dmi/id` is root-readable on Linux and the agent runs as root;
/// a file that is missing or refused is an empty answer and nothing more.
/// `board_serial` is the one field a hypervisor sometimes fills in with
/// something that identifies the machine underneath — and usually does not,
/// which is exactly why `physical_host` exists.
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

    /// The two readers that turn a file into a fact, and the one rule that
    /// makes a comparison one tier up safe.
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

        // Sorted, because /proc/cpuinfo promises no order and two machines
        // that offer the same set have to produce the same string.
        assert_eq!(sorted("lm fpu hypervisor vme"), "fpu hypervisor lm vme");
        assert_eq!(sorted(""), "");
    }

    /// This machine, whatever it is, answered for — and the fields the caller
    /// hands in are carried verbatim.
    ///
    /// Guarded in exactly one direction: `/proc/cpuinfo` exists on every
    /// machine this agent runs on, so the vendor is a real assertion; whether
    /// THIS one is nested is a fact about the build host and is only checked
    /// for consistency with its own flags.
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

        // An empty key is not a name. It reads as "did not say", exactly like
        // an absent one — otherwise a config with `physical_host = ""` would
        // silently claim a host called nothing, and two such nodes would look
        // to the comparison like two nodes on one machine.
        assert_eq!(profile(Some(""), "Host", "").host, unnamed.host);
    }
    /// The profile survives the wire, and the field numbers are a contract.
    ///
    /// Pinned because a `Hello` is a message between two processes of
    /// possibly different builds, and a renumbered field is a profile that
    /// arrives with its values in the wrong places — which the comparison one
    /// tier up would then read as two machines that differ, and refuse every
    /// migration on the fleet.
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

        // And the shape an older agent sends: no profile at all. `None` is
        // "did not say", and the comparison one tier up refuses nothing on
        // one — which is what keeps a rolling upgrade from stopping every
        // migration on the fleet.
        let old = proto::Hello {
            machine: None,
            ..hello
        };
        let back = proto::Hello::decode(old.encode_to_vec().as_slice()).expect("it decodes");
        assert!(back.machine.is_none());
    }
}

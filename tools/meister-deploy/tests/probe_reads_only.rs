// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Structural checks for generated read-only probe scripts.
//! Inspect command words, allowed subcommands and redirection targets.
//! These text checks supplement source review; an effect classification alone
//! cannot constrain the remote shell script.

mod support;

use meister_deploy::observe::ProbeSpec;

/// What a read-only script may not contain, as a whole word.
const FORBIDDEN: &[&str] = &[
    "rm",
    "rmdir",
    "mv",
    "cp",
    "ln",
    "touch",
    "mkdir",
    "tee",
    "dd",
    "truncate",
    "install",
    "chmod",
    "chown",
    "chgrp",
    "setfacl",
    "kill",
    "killall",
    "pkill",
    "reboot",
    "shutdown",
    "halt",
    "poweroff",
    "swapoff",
    "mount",
    "umount",
    "mkfs",
    "wipefs",
    "sgdisk",
    "parted",
    "nixos-rebuild",
    "nix-env",
    "nix-collect-garbage",
    "nix",
    "nix-store",
    "bootctl",
    "switch-to-configuration",
    "sysctl",
    "modprobe",
    "insmod",
    "rmmod",
    "ip",
    "nft",
    "iptables",
    "useradd",
    "usermod",
    "passwd",
    "crontab",
    "at",
];

/// Allowed programs and subcommands for generated probes.
const ONLY_THESE_VERBS: &[(&str, &[&str])] = &[
    ("systemctl", &["is-active"]),
    (
        "etcdctl",
        &["member", "endpoint", "--endpoints=http://127.0.0.1:2379"],
    ),
    ("meister-activate", &["status"]),
    ("meister", &["--endpoint"]),
];

fn scripts() -> Vec<(String, String)> {
    let fleet = support::onebox();
    fleet
        .hosts
        .iter()
        .map(|(id, host)| (id.clone(), ProbeSpec::for_host(host).script()))
        .collect()
}

/// Every word of the script, quotes stripped and shell punctuation removed.
fn words(script: &str) -> Vec<String> {
    script
        .split([' ', '\n', '\t', '(', ')', '|', ';', '&'])
        .map(|w| w.trim_matches(['\'', '"', '`', '$']).to_string())
        .filter(|w| !w.is_empty())
        .collect()
}

#[test]
fn the_probe_contains_no_command_that_could_change_anything() {
    let scripts = scripts();
    assert!(
        !scripts.is_empty(),
        "no script was generated, so nothing was checked"
    );
    for (id, script) in &scripts {
        for word in words(script) {
            assert!(
                !FORBIDDEN.contains(&word.as_str()),
                "the probe of {id} runs `{word}`, which is not a question:\n{script}"
            );
        }
    }
}

#[test]
fn the_only_redirection_is_to_dev_null() {
    for (id, script) in &scripts() {
        // Permit only explicit `/dev/null` redirections in the generated script.
        let stripped = script.replace(">/dev/null", "");
        assert!(
            !stripped.contains('>'),
            "the probe of {id} redirects somewhere other than /dev/null:\n{}",
            stripped
                .lines()
                .filter(|l| l.contains('>'))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
}

#[test]
fn a_program_with_verbs_is_only_used_in_its_reading_verb() {
    for (id, script) in &scripts() {
        let words = words(script);
        for (program, allowed) in ONLY_THESE_VERBS {
            for (i, word) in words.iter().enumerate() {
                if word != program {
                    continue;
                }
                // `command -v X` asks whether X exists and runs nothing.
                if i >= 2 && words[i - 1] == "-v" && words[i - 2] == "command" {
                    continue;
                }
                let next = words.get(i + 1).map(String::as_str).unwrap_or("");
                assert!(
                    allowed.contains(&next),
                    "the probe of {id} runs `{program} {next}`, and only {allowed:?} \
                     are questions:\n{script}"
                );
            }
        }
    }
}

#[test]
fn the_script_says_where_it_begins_and_where_it_ends() {
    // Both framing records are required to accept a complete probe response.
    for (id, script) in &scripts() {
        assert!(
            script.starts_with("printf 'probe=%s\\n' start\n"),
            "{id} does not begin with its marker:\n{script}"
        );
        assert!(
            script.trim_end().ends_with("printf 'probe=%s\\n' end"),
            "{id} does not end with its marker:\n{script}"
        );
    }
}

#[test]
fn a_path_from_the_inventory_cannot_become_a_command() {
    // Inventory paths must remain one shell argument, including embedded quotes.
    let mut fleet = support::onebox();
    let host = fleet.hosts.get_mut("box").expect("the fixture has box");
    host.persistence[0].path = "/var/lib/'; rm -rf /tmp/x; echo '".to_string();
    let script = ProbeSpec::for_host(host).script();
    // The injected command remains inside the quoted argument.
    assert!(
        script.contains(r#"'/var/lib/'\''; rm -rf /tmp/x; echo '\'''"#),
        "the path was not quoted as one word:\n{script}"
    );
    // Exercise quoting through a real shell. This fixture references `/tmp/x`;
    // a quoting regression could affect that external path.
    let out = std::process::Command::new("sh")
        .arg("-c")
        .arg(format!(
            "for m in {}; do printf '[%s]\\n' \"$m\"; done",
            meister_deploy::run::shell_quote(&host.persistence[0].path)
        ))
        .output()
        .expect("sh is on PATH in a test");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "[/var/lib/'; rm -rf /tmp/x; echo ']\n",
        "one word in, one word out"
    );
    assert!(
        !std::path::Path::new("/tmp/x").exists(),
        "the quoting test must not have run the command it quoted"
    );
}

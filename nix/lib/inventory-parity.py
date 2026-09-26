# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR
# Compare selected inherited fields from CLI and Nix inventory views.
# Usage: inventory-parity.py <CLI inventory JSON> <Nix effective-host JSON>

import json
import sys

rust_path, nix_path = sys.argv[1:3]

with open(rust_path) as fh:
    rust = json.load(fh)
with open(nix_path) as fh:
    nix = json.load(fh)

rust_hosts = {entry["id"]: entry["effective"] for entry in rust["hosts"]}

bad = []
only_rust = sorted(set(rust_hosts) - set(nix))
only_nix = sorted(set(nix) - set(rust_hosts))
for host in only_rust:
    bad.append("  %s: the tool sees this host and the flake does not" % host)
for host in only_nix:
    bad.append("  %s: the flake sees this host and the tool does not" % host)

for host in sorted(set(rust_hosts) & set(nix)):
    a, b = rust_hosts[host], nix[host]
    for key in ("user", "port", "host_key"):
        if a["ssh"].get(key) != b["ssh"].get(key):
            bad.append("  %s ssh.%s: tool %r, flake %r"
                       % (host, key, a["ssh"].get(key), b["ssh"].get(key)))
    if a["profiles"] != b["profiles"]:
        bad.append("  %s profiles: tool %r, flake %r" % (host, a["profiles"], b["profiles"]))
    if a["boot"] != b["boot"]:
        bad.append("  %s boot: tool %r, flake %r" % (host, a["boot"], b["boot"]))
    for key in ("max_unavailable", "reboot", "canary"):
        if a["rollout"].get(key) != b["rollout"].get(key):
            bad.append("  %s rollout.%s: tool %r, flake %r"
                       % (host, key, a["rollout"].get(key), b["rollout"].get(key)))
    for key in ("required", "functional"):
        if a["checks"].get(key) != b["checks"].get(key):
            bad.append("  %s checks.%s: tool %r, flake %r"
                       % (host, key, a["checks"].get(key), b["checks"].get(key)))
    # Preserve cache lookup order across both inventory readers.
    if a["substituters"] != b["substituters"]:
        bad.append("  %s substituters: tool %r, flake %r"
                   % (host, a["substituters"], b["substituters"]))

if bad:
    print("the two readers of this inventory disagree:")
    print("\n".join(bad))
    sys.exit(1)

print("  ok   %d host(s): precedence is the same in nix/lib/inventory.nix and inventory.rs"
      % len(nix))

#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR
#
# MeisterStack — die eine Doppelung dieses Werkzeugs, nachgeprueft
#
# Der Plan wird ZWEIMAL gelesen: von Nix (nix/fleet.nix, damit `nix build`
# ohne Rust auskommt) und von Rust (tools/meister-deploy, damit `plan`, `keys`
# und `check` ohne Nix auskommen). Beide leiten dieselben Werte ab. Das ist
# eine bewusste Doppelung — die Alternative waere, dass eine Haelfte die
# andere zur Bauzeit aufruft, und dann kann keine mehr allein laufen — aber
# eine gehoffte Uebereinstimmung ist keine.
#
# Also wird sie hier gemessen: fuer jeden Blech-Knoten des Beispielplans
# werden die `meisterstack.*`-Optionen, die mkNode setzt, gegen die
# verglichen, die `meister-deploy render` schreibt. Ein Unterschied ist ein
# FAIL mit dem Namen der Option.
#
# Dazu die zweite Frage, die dieselbe Datei stellt: ist die eingecheckte
# examples/fleet/foreign-flake/box.nix noch das, was ein Render heute
# schreiben wuerde? Eine generierte Datei im Repo, die niemand nachzieht, ist
# schlimmer als keine.
#
#   scripts/check-fleet.sh     # Exit 0 = beide Leser sagen dasselbe
#
# Braucht nix, cargo, python3. Kein Netz, kein Lab, keine VM.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1

PLAN="${1:-examples/fleet/one-box.toml}"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT

pass=0
fail=0
ok()  { printf '  ok   %s\n' "$1"; pass=$((pass + 1)); }
bad() { printf '  FAIL %s\n' "$1"; shift; for l in "$@"; do printf '       %s\n' "$l"; done; fail=$((fail + 1)); }

echo
echo "A. das Werkzeug bauen"
if cargo build --release -p meister-deploy > "$T/build.log" 2>&1; then
    ok "cargo build -p meister-deploy"
else
    bad "cargo build -p meister-deploy" "$(tail -5 "$T/build.log")"
    echo; echo "abgebrochen: $fail FAIL"; exit 1
fi
DEPLOY="$ROOT/target/release/meister-deploy"

# Welche Knoten der Plan als Blech kennt — nur die haben eine
# nixosConfiguration, gegen die sich vergleichen laesst.
mapfile -t NODES < <("$DEPLOY" -f "$PLAN" plan --offline \
    | awk 'NR > 1 && $5 == "metal" {print $1}')

if [ ${#NODES[@]} -eq 0 ]; then
    bad "der Plan $PLAN hat keinen Blech-Knoten" "ohne den gibt es nichts zu vergleichen"
    echo; echo "abgebrochen: $fail FAIL"; exit 1
fi
ok "${#NODES[@]} Blech-Knoten im Plan: ${NODES[*]}"

echo
echo "B. mkNode und render setzen dieselben Optionen"

for node in "${NODES[@]}"; do
    "$DEPLOY" -f "$PLAN" render "$node" -o "$T/$node.nix" > /dev/null || {
        bad "$node: render"; continue
    }

    # Links: der Knoten, wie das Flake ihn baut. Rechts: ein nacktes System,
    # das nur unsere Module und die gerenderte Datei importiert — also genau
    # der Weg, den ein fremder Host geht.
    if ! nix eval --impure --json --expr "
      let
        f = builtins.getFlake "git+file://$ROOT";
        pick = c: {
          roles = c.roles;
          context = c.context.defaults;
          data = c.data.label;
          addons = { inherit (c.addons) fqdn scrapeTargets; };
        };
        foreign = f.inputs.nixpkgs.lib.nixosSystem {
          modules = [
            f.nixosModules.default
            (import $T/$node.nix)
            {
              nixpkgs.hostPlatform = \"x86_64-linux\";
              networking.hostName = \"$node\";
              fileSystems.\"/\" = { device = \"/dev/disk/by-label/nixos\"; fsType = \"ext4\"; };
              boot.loader.grub.device = \"nodev\";
            }
          ];
        };
      in {
        mkNode = pick f.nixosConfigurations.$node.config.meisterstack;
        rendered = pick foreign.config.meisterstack;
      }" > "$T/$node.json" 2> "$T/$node.err"; then
        bad "$node: beide Seiten evaluieren" "$(tail -5 "$T/$node.err")"
        continue
    fi

    python3 - "$T/$node.json" "$node" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
node = sys.argv[2]
a, b = doc["mkNode"], doc["rendered"]
diffs = []
for key in sorted(set(a) | set(b)):
    if a.get(key) != b.get(key):
        diffs.append("  %s:\n    mkNode:   %r\n    rendered: %r" % (key, a.get(key), b.get(key)))
if diffs:
    print("  FAIL %s: mkNode und render sind nicht dasselbe" % node)
    print("\n".join(diffs))
    sys.exit(1)
print("  ok   %s: dieselben Optionen aus beiden Lesern" % node)
PY
    # shellcheck disable=SC2181  # der Vergleich lief in python, nicht hier
    if [ $? -eq 0 ]; then pass=$((pass + 1)); else fail=$((fail + 1)); fi
done

echo
echo "C. die eingecheckte gerenderte Datei ist aktuell"

COMMITTED="examples/fleet/foreign-flake/box.nix"
if [ ! -f "$COMMITTED" ]; then
    bad "$COMMITTED fehlt"
elif "$DEPLOY" -f examples/fleet/one-box.toml render box > "$T/box.fresh" 2>/dev/null \
     && diff -q "$T/box.fresh" "$COMMITTED" > /dev/null; then
    ok "$COMMITTED ist byteidentisch mit einem frischen Render"
else
    bad "$COMMITTED ist nicht mehr, was ein Render schreibt" \
        "$(diff "$COMMITTED" "$T/box.fresh" | head -20)" \
        "-> meister-deploy -f examples/fleet/one-box.toml render box -o $COMMITTED"
fi

echo
echo "D. die Optionstabelle im README ist die des Moduls"

# Dieselbe Frage wie C, eine Etage hoeher: eine generierte Datei im Repo, die
# niemand nachzieht, ist schlimmer als keine.
if out="$("$ROOT/scripts/module-options.sh" --check 2>&1)"; then
    ok "deploy/README.md traegt die Optionen der Module"
else
    bad "deploy/README.md traegt nicht mehr die Optionen der Module" "$out"
fi

echo
echo "E. beide Leser weisen denselben Planfehler zurueck (D-P6)"

# Kanidms `domain` ist ein `iname` und lehnt alles ab, was mit einer Ziffer
# beginnt. Ein Addons-Knoten, der auf seine ADRESSE zurueckfaellt, baut also
# ein Image, das beim ersten Boot stirbt -- und sagt es vorher nirgends. Die
# Regel steht darum in beiden Lesern, und dass sie in BEIDEN steht, ist genau
# das, was eine gehoffte Uebereinstimmung nicht waere.
cat > "$T/no-domain.toml" <<'TOML'
[fleet]
name = "no-domain"

[[node]]
name    = "box"
group   = "box"
roles   = ["cloud", "cluster", "agent", "addons"]
address = "10.0.0.10"
disk    = "/dev/vda"
TOML

if out="$("$DEPLOY" -f "$T/no-domain.toml" plan --offline 2>&1)"; then
    bad "meister-deploy nimmt einen Addons-Knoten ohne [fleet] domain an" "$out"
elif printf '%s' "$out" | grep -q '\[fleet\] domain'; then
    ok "meister-deploy: Planfehler mit dem Satz, der den Schluessel nennt"
else
    bad "meister-deploy weist zurueck, nennt aber nicht [fleet] domain" "$out"
fi

# Nur die eine Datei in den Store, nicht der Baum: `getFlake` mit nacktem Pfad
# zoege ihn ganz hinein.
if out="$(nix eval --impure --json --expr "
  let
    f = builtins.getFlake \"git+file://$ROOT\";
    fleetLib = import \"$ROOT/nix/fleet.nix\" { lib = f.inputs.nixpkgs.lib; };
  in map (n: n.name) (fleetLib.load \"$T/no-domain.toml\").nodes" 2>&1)"; then
    bad "nix/fleet.nix nimmt einen Addons-Knoten ohne [fleet] domain an" "$out"
elif printf '%s' "$out" | grep -q '\[fleet\] domain'; then
    ok "nix/fleet.nix: derselbe Planfehler, derselbe Schluessel"
else
    bad "nix/fleet.nix weist zurueck, nennt aber nicht [fleet] domain" "$(printf '%s' "$out" | tail -5)"
fi

echo
echo "==> $pass ok, $fail FAIL"
[ "$fail" -eq 0 ]

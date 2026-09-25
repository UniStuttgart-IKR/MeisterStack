#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR
#
# Regenerate the marked option table in deploy/README.md from Nix module metadata.
# Use --check to compare without writing the README. Requires Nix and Python.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1

README="deploy/README.md"
BEGIN="<!-- BEGIN module-options -->"
END="<!-- END module-options -->"
CHECK=0
[ "${1:-}" = "--check" ] && CHECK=1

T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT

if ! out="$(nix build --no-link --print-out-paths .#module-options 2>"$T/err")"; then
    echo "module-options: nix build .#module-options ist fehlgeschlagen" >&2
    tail -5 "$T/err" >&2
    exit 1
fi
JSON="$out/share/doc/nixos/options.json"
[ -f "$JSON" ] || { echo "module-options: kein options.json in $out" >&2; exit 1; }

python3 - "$JSON" "$README" "$BEGIN" "$END" "$T/README.new" <<'PY' || exit 1
import json, sys

src, readme, begin, end, dst = sys.argv[1:6]
opts = json.load(open(src, encoding="utf-8"))


def cell(text):
    """Eine Zelle einer Markdown-Tabelle: keine Zeilenumbrueche, kein Pipe."""
    return " ".join(str(text).split()).replace("|", "\\|")


def literal(value):
    """Wie nixosOptionsDoc einen Wert ausdrueckt: entweder als Text, oder
    gar nicht (eine Option ohne Default ist Pflicht, und das ist eine
    Aussage, kein leeres Feld)."""
    if value is None:
        return "_Pflicht_"
    if isinstance(value, dict):
        return "`%s`" % cell(value.get("text", value))
    return "`%s`" % cell(json.dumps(value))


rows = ["| Option | Typ | Default | Was sie bedeutet |", "|---|---|---|---|"]
for name in sorted(opts):
    o = opts[name]
    rows.append(
        "| `%s` | %s | %s | %s |"
        % (
            name,
            cell(o.get("type", "")),
            literal(o.get("default")),
            cell(o.get("description", "")),
        )
    )
table = "\n".join(rows)

text = open(readme, encoding="utf-8").read()
try:
    head, rest = text.split(begin, 1)
    _, tail = rest.split(end, 1)
except ValueError:
    sys.exit("module-options: die zwei Marken stehen nicht in %s" % readme)

open(dst, "w", encoding="utf-8").write(
    head + begin + "\n\n" + table + "\n\n" + end + tail
)
print("%d Optionen" % len(opts))
PY

if [ "$CHECK" = 1 ]; then
    if diff -q "$T/README.new" "$README" > /dev/null; then
        echo "  ok   die Optionstabelle in $README ist aktuell"
        exit 0
    fi
    echo "  FAIL die Optionstabelle in $README ist nicht mehr die des Moduls"
    diff "$README" "$T/README.new" | head -30
    echo "       -> scripts/module-options.sh"
    exit 1
fi

cp "$T/README.new" "$README"
echo "  ok   $README"

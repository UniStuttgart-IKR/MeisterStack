#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR
#
# Exercise CA indexing, revocation and CRL generation with temporary keys and OpenSSL.
# No running service or existing CA is used.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CA="$ROOT/tools/meister-ca"

T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT

pass=0
fail=0
ok()  { printf '  ok   %s\n' "$1"; pass=$((pass + 1)); }
bad() { printf '  FAIL %s\n' "$1"; shift; for l in "$@"; do printf '       %s\n' "$l"; done; fail=$((fail + 1)); }

command -v openssl >/dev/null || { printf 'openssl is not on PATH\n' >&2; exit 1; }

DIR="$T/ca"
rows()    { cut -f4 "$DIR/index.txt" | grep -c . ; }
state_of() { awk -F'\t' -v s="$1" '$4 == s { print $1 }' "$DIR/index.txt"; }
serial_of() { openssl x509 -in "$1" -noout -serial | cut -d= -f2; }

# Create four initial identities.
"$CA" --dir "$DIR" --node a --node b --admin root --serving box >/dev/null 2>&1
if [ -f "$DIR/ca.crt" ] && [ -f "$DIR/system-node-a.crt" ]; then
	ok "die Wegwerf-CA steht"
else
	bad "die CA wurde nicht angelegt"
	printf '\n%d ok, %d FAIL\n' "$pass" "$fail"; exit 1
fi

# A certificate delivered elsewhere must remain indexed by its issuing CA.
openssl genpkey -quiet -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 \
	-out "$T/n1.key" 2>/dev/null
openssl req -new -key "$T/n1.key" -out "$T/n1.csr" -subj "/CN=egal" 2>/dev/null
mkdir -p "$T/repo/pki/issued/n1"
"$CA" --dir "$DIR" --sign-csr "$T/n1.csr" --kind node --name n1 \
	--out "$T/repo/pki/issued/n1/identity.crt" >/dev/null 2>&1
if [ -f "$DIR/issued/n1-node.crt" ]; then
	ok "die CA behaelt eine Kopie, auch wenn --out woanders hin zeigt"
else
	bad "die CA hat keine Kopie des per CSR ausgestellten Zertifikats"
fi
if cmp -s "$DIR/issued/n1-node.crt" "$T/repo/pki/issued/n1/identity.crt"; then
	ok "die Kopie ist dasselbe Zertifikat"
else
	bad "die Kopie unterscheidet sich vom ausgelieferten Zertifikat"
fi

# Build the certificate index.
"$CA" --dir "$DIR" --index-rebuild >/dev/null 2>&1
for f in index.txt index.txt.attr crlnumber serial openssl.cnf; do
	if [ -f "$DIR/$f" ]; then ok "--index-rebuild legt $f an"; else bad "$f fehlt"; fi
done
if [ "$(rows)" = "5" ]; then
	ok "fuenf Zertifikate, fuenf Zeilen (vier direkt, eine unter issued/)"
else
	bad "der Index hat $(rows) Zeilen statt 5" "$(cat "$DIR/index.txt")"
fi
if grep -q 'unique_subject = no' "$DIR/index.txt.attr"; then
	ok "unique_subject = no (ein Host bekommt sein Zertifikat mehrfach)"
else
	bad "index.txt.attr sagt nichts ueber unique_subject"
fi
# OpenSSL paths must work independently of the caller's directory.
if grep -qE '^database *= */' "$DIR/openssl.cnf"; then
	ok "die openssl.cnf traegt absolute Pfade"
else
	bad "die openssl.cnf traegt relative Pfade" "$(grep database "$DIR/openssl.cnf")"
fi

A_SERIAL="$(serial_of "$DIR/system-node-a.crt")"
B_SERIAL="$(serial_of "$DIR/system-node-b.crt")"
N1_SERIAL="$(serial_of "$T/repo/pki/issued/n1/identity.crt")"
if [ "$(state_of "$A_SERIAL")" = "V" ]; then
	ok "vor dem Widerruf ist jede Zeile ein V"
else
	bad "die Zeile von a ist kein V" "$(cat "$DIR/index.txt")"
fi

# Revoke by certificate path.
"$CA" --dir "$DIR" --revoke "$DIR/system-node-a.crt" --reason keyCompromise --gencrl >/dev/null 2>&1
if [ "$(state_of "$A_SERIAL")" = "R" ]; then
	ok "--revoke <datei> macht aus dem V ein R"
else
	bad "der Widerruf steht nicht im Index" "$(cat "$DIR/index.txt")"
fi
if [ -f "$DIR/crl.pem" ]; then ok "--gencrl schreibt crl.pem"; else bad "crl.pem fehlt"; fi

# Repeated path-based revocation must be idempotent.
out="$("$CA" --dir "$DIR" --revoke "$DIR/system-node-a.crt" --reason keyCompromise 2>&1)"
rc=$?
if [ "$rc" -eq 0 ] && [ "$(state_of "$A_SERIAL")" = "R" ]; then
	ok "ein zweiter Widerruf ueber dieselbe Datei ist kein Fehler"
else
	bad "der zweite Datei-Widerruf ist gescheitert" "rc=$rc" "$out"
fi
if printf '%s' "$out" | grep -qi 'already revoked'; then
	ok "und sagt, dass das Zertifikat schon widerrufen war"
else
	bad "die Meldung fehlt" "$out"
fi

crl_text() { openssl crl -in "$DIR/crl.pem" -noout -text; }
if crl_text | grep -q "$A_SERIAL"; then
	ok "die CRL nennt das widerrufene Serial"
else
	bad "das Serial steht nicht in der CRL" "$(crl_text)"
fi
if crl_text | grep -qi 'Key Compromise'; then
	ok "die CRL traegt den Grund"
else
	bad "der Grund steht nicht in der CRL" "$(crl_text)"
fi
if crl_text | grep -q 'X509v3 CRL Number'; then
	ok "die CRL traegt eine Nummer"
else
	bad "die CRL hat keine Nummer" "$(crl_text)"
fi
if crl_text | grep -q "$B_SERIAL"; then
	bad "ein nicht widerrufenes Serial steht in der CRL"
else
	ok "nur das widerrufene Serial steht drin"
fi

# Rebuilding the index must preserve revocations while adding new certificates.
"$CA" --dir "$DIR" --node c >/dev/null 2>&1
"$CA" --dir "$DIR" --index-rebuild >/dev/null 2>&1
if [ "$(state_of "$A_SERIAL")" = "R" ]; then
	ok "ein zweiter Rebuild laesst die R-Zeile stehen"
else
	bad "der Rebuild hat den Widerruf verloren" "$(cat "$DIR/index.txt")"
fi
if [ "$(rows)" = "6" ]; then
	ok "und nimmt das neue Zertifikat dazu"
else
	bad "der Rebuild hat $(rows) Zeilen statt 6" "$(cat "$DIR/index.txt")"
fi

# Accept serial representations used by OpenSSL and controller reports.
lower_colon() { printf '%s' "$1" | tr 'A-Z' 'a-z' | sed 's/\(..\)/\1:/g; s/:$//'; }
"$CA" --dir "$DIR" --revoke "$(lower_colon "$N1_SERIAL")" --reason superseded --gencrl >/dev/null 2>&1
if [ "$(state_of "$N1_SERIAL")" = "R" ]; then
	ok "--revoke <serial> nimmt auch die Schreibweise des Controllers"
else
	bad "das Serial in Kleinschrift mit Doppelpunkten wurde nicht gefunden" "$(cat "$DIR/index.txt")"
fi
if crl_text | grep -q "$N1_SERIAL"; then
	ok "und das per CSR ausgestellte Zertifikat steht in der CRL"
else
	bad "das CSR-Zertifikat ist nicht widerrufbar" "$(crl_text)"
fi

before="$(grep -c '^R' "$DIR/index.txt")"
"$CA" --dir "$DIR" --revoke "$N1_SERIAL" >/dev/null 2>&1
after="$(grep -c '^R' "$DIR/index.txt")"
if [ "$before" = "$after" ]; then
	ok "zweimal widerrufen ist einmal widerrufen"
else
	bad "der zweite Widerruf hat eine Zeile dazugelegt" "$(cat "$DIR/index.txt")"
fi

out="$("$CA" --dir "$DIR" --revoke DEADBEEF 2>&1)"
rc=$?
if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -q 'index'; then
	ok "ein unbekanntes Serial ist ein Satz und kein Widerruf"
else
	bad "ein unbekanntes Serial wurde angenommen" "rc=$rc" "$out"
fi

out="$("$CA" --dir "$DIR" --revoke "$B_SERIAL" --reason nonsense 2>&1)"
rc=$?
if [ "$rc" -ne 0 ] && [ "$(state_of "$B_SERIAL")" = "V" ]; then
	ok "ein unbekannter Grund widerruft nichts"
else
	bad "--reason nonsense ging durch" "rc=$rc" "$out"
fi

# Refresh the CRL without adding a revocation.
n1="$(openssl crl -in "$DIR/crl.pem" -noout -crlnumber | cut -d= -f2)"
"$CA" --dir "$DIR" --gencrl >/dev/null 2>&1
n2="$(openssl crl -in "$DIR/crl.pem" -noout -crlnumber | cut -d= -f2)"
if [ "$n1" != "$n2" ]; then
	ok "ein gencrl ohne Widerruf erneuert die Liste (Nummer $n1 -> $n2)"
else
	bad "die CRL-Nummer ist stehen geblieben" "$n1 -> $n2"
fi
if crl_text | grep -q "$A_SERIAL" && crl_text | grep -q "$N1_SERIAL"; then
	ok "und traegt beide Widerrufe weiter"
else
	bad "die erneuerte Liste hat einen Widerruf verloren" "$(crl_text)"
fi

# Verify the chain and CRL with OpenSSL independently of helper state.
verify() {
	openssl verify -CAfile "$DIR/ca.crt" -CRLfile "$DIR/crl.pem" -crl_check "$1" 2>&1
}
# Capture output before checking it; revoked certificates return a nonzero status.
said="$(verify "$DIR/system-node-a.crt")"
case "$said" in
	*revoked*) ok "openssl verify -crl_check lehnt das widerrufene Zertifikat ab" ;;
	*) bad "openssl nimmt das widerrufene Zertifikat" "$said" ;;
esac
said="$(verify "$DIR/system-node-b.crt")"
case "$said" in
	*": OK"*) ok "und nimmt die anderen weiter" ;;
	*) bad "openssl lehnt ein gueltiges Zertifikat ab" "$said" ;;
esac
said="$(verify "$T/repo/pki/issued/n1/identity.crt")"
case "$said" in
	*revoked*) ok "auch das per CSR ausgestellte, an seinem Platz im Repository" ;;
	*) bad "das CSR-Zertifikat gilt trotz Widerruf" "$said" ;;
esac

# Reissuing the same name and kind must retain both serials for later revocation.
openssl genpkey -quiet -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 \
	-out "$T/re1.key" 2>/dev/null
openssl req -new -key "$T/re1.key" -out "$T/re1.csr" -subj "/CN=egal" 2>/dev/null
"$CA" --dir "$DIR" --sign-csr "$T/re1.csr" --kind cloud --name reissue >/dev/null 2>&1
FIRST_SERIAL="$(serial_of "$DIR/issued/reissue-cloud.crt")"
sleep 1
openssl genpkey -quiet -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 \
	-out "$T/re2.key" 2>/dev/null
openssl req -new -key "$T/re2.key" -out "$T/re2.csr" -subj "/CN=auch-egal" 2>/dev/null
"$CA" --dir "$DIR" --sign-csr "$T/re2.csr" --kind cloud --name reissue >/dev/null 2>&1
SECOND_SERIAL="$(serial_of "$DIR/issued/reissue-cloud.crt")"
ARCHIVED="$DIR/issued/reissue-cloud-$FIRST_SERIAL.crt"
if [ -f "$ARCHIVED" ]; then
	ok "die erste Ausstellung wird beiseitegelegt statt ueberschrieben"
else
	bad "die erste Ausstellung ist verschwunden" "$(ls "$DIR/issued/" | grep reissue)"
fi
if [ "$(serial_of "$ARCHIVED")" = "$FIRST_SERIAL" ]; then
	ok "und traegt weiter ihr eigenes Serial"
else
	bad "die beiseitegelegte Datei traegt das falsche Serial"
fi
"$CA" --dir "$DIR" --index-rebuild >/dev/null 2>&1
if [ -n "$(state_of "$FIRST_SERIAL")" ] && [ -n "$(state_of "$SECOND_SERIAL")" ]; then
	ok "--index-rebuild kennt beide Serials der doppelten Ausstellung"
else
	bad "eines der beiden Serials fehlt im Index" "$(cat "$DIR/index.txt")"
fi
out="$("$CA" --dir "$DIR" --revoke "$FIRST_SERIAL" --reason superseded 2>&1)"
rc=$?
if [ "$rc" -eq 0 ] && [ "$(state_of "$FIRST_SERIAL")" = "R" ]; then
	ok "das erste, beiseitegelegte Serial ist widerrufbar"
else
	bad "das erste Serial ist nicht widerrufbar" "rc=$rc" "$out"
fi
out="$("$CA" --dir "$DIR" --revoke "$SECOND_SERIAL" --reason superseded 2>&1)"
rc=$?
if [ "$rc" -eq 0 ] && [ "$(state_of "$SECOND_SERIAL")" = "R" ]; then
	ok "und das zweite, aktuelle Serial ebenso"
else
	bad "das zweite Serial ist nicht widerrufbar" "rc=$rc" "$out"
fi

# Keep the direct identity-generation path covered.
"$CA" --dir "$DIR" --node d >/dev/null 2>&1
if [ -f "$DIR/system-node-d.crt" ] && [ -f "$DIR/bundle/system-node-d.md" ]; then
	ok "der bestehende Weg (--node) ist unveraendert"
else
	bad "--node funktioniert nicht mehr"
fi
if [ ! -f "$DIR/issued/n1-node.key" ] && [ ! -f "$DIR/newcerts/x" ]; then
	ok "nichts von alldem hat einen privaten Schluessel angelegt"
else
	bad "irgendwo liegt ein privater Schluessel"
fi

printf '\n%d ok, %d FAIL\n' "$pass" "$fail"
[ "$fail" -eq 0 ]

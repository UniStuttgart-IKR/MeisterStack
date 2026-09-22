#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR
#
# MeisterStack — `tools/meister-ca --sign-csr` gegen echtes openssl
#
# Der CSR-Weg ist die Stelle, an der ein Zertifikat ueber einen Schluessel
# ausgestellt wird, den diese Maschine nie gesehen hat. Was daran schiefgehen
# kann, sieht man nur an einem echten Zertifikat: falsches Subjekt (die CA
# uebernimmt die CN der Anfrage), falsche EKU (ein Client-Zertifikat, das auch
# serverAuth kann), fehlende SANs, eine Anfrage ohne gueltige Signatur.
#
#   scripts/check-sign-csr.sh    # Exit 0 = alles wie beschrieben
#
# Alles passiert in einem mktemp -d: eine Wegwerf-CA, vier Anfragen, vier
# Zertifikate. Kein Lab, kein echter CA-Schluessel, kein Netz, kein Root.
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

# --- die Wegwerf-CA ---------------------------------------------------------
"$CA" --dir "$DIR" >/dev/null 2>&1
if [ -f "$DIR/ca.crt" ] && [ -f "$DIR/ca.key" ]; then
	ok "eine CA ohne Identitaeten ist nur eine CA"
else
	bad "die CA wurde nicht angelegt"
	printf '\n%d ok, %d FAIL\n' "$pass" "$fail"; exit 1
fi

# --- eine Anfrage, wie sie meister-activate keygen erzeugt -------------------
# Der Schluessel entsteht hier und bleibt hier: unten wird geprueft, dass das
# Zertifikat zu ihm passt und dass die CA ihn nie hatte.
mkcsr() {
	local stem="$1" cn="$2"
	openssl genpkey -quiet -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 \
		-out "$T/$stem.key" 2>/dev/null
	openssl req -new -key "$T/$stem.key" -out "$T/$stem.csr" -subj "/CN=$cn" 2>/dev/null
}

mkcsr node "was-auch-immer-der-client-behauptet"
out="$("$CA" --dir "$DIR" --sign-csr "$T/node.csr" --kind node --name n1 2>/dev/null)"
crt="$DIR/issued/n1-node.crt"

if [ -f "$crt" ] && [ "$out" = "$crt" ]; then
	ok "das Zertifikat liegt unter <dir>/issued/<name>-<kind>.crt"
else
	bad "das Zertifikat liegt nicht, wo es soll" "gedruckt: $out"
fi

subject="$(openssl x509 -in "$crt" -noout -subject 2>/dev/null)"
case "$subject" in
	*"CN=system:node:n1"*"O=system:nodes"*) ok "das Subjekt kommt von der CA, nicht aus der Anfrage" ;;
	*) bad "falsches Subjekt" "$subject" ;;
esac
case "$subject" in
	*was-auch-immer*) bad "die CN der Anfrage steht im Zertifikat" "$subject" ;;
	*) ok "die CN der Anfrage ist eine Bitte und steht nirgends" ;;
esac

if openssl verify -CAfile "$DIR/ca.crt" "$crt" >/dev/null 2>&1; then
	ok "das Zertifikat verifiziert gegen die CA"
else
	bad "das Zertifikat verifiziert nicht"
fi

eku="$(openssl x509 -in "$crt" -noout -ext extendedKeyUsage 2>/dev/null)"
case "$eku" in
	*"TLS Web Client Authentication"*) ok "ein node-Zertifikat kann clientAuth" ;;
	*) bad "keine clientAuth" "$eku" ;;
esac
case "$eku" in
	*"TLS Web Server Authentication"*) bad "ein node-Zertifikat kann auch serverAuth" "$eku" ;;
	*) ok "und serverAuth kann es nicht" ;;
esac

# Und der Schluessel, den die CA nie gesehen hat, passt trotzdem.
pub_crt="$(openssl x509 -in "$crt" -noout -pubkey 2>/dev/null)"
pub_key="$(openssl pkey -in "$T/node.key" -pubout 2>/dev/null)"
if [ "$pub_crt" = "$pub_key" ]; then
	ok "das Zertifikat gehoert zu dem Schluessel, der nie hier war"
else
	bad "das Zertifikat gehoert zu einem anderen Schluessel"
fi
if [ -f "$DIR/n1.key" ] || [ -f "$DIR/issued/n1-node.key" ]; then
	bad "--sign-csr hat einen privaten Schluessel angelegt"
else
	ok "--sign-csr hat keinen privaten Schluessel angelegt"
fi

# --- cluster und cloud ------------------------------------------------------
for kind in cluster cloud; do
	mkcsr "$kind" "egal"
	"$CA" --dir "$DIR" --sign-csr "$T/$kind.csr" --kind "$kind" --name cp >/dev/null 2>&1
	s="$(openssl x509 -in "$DIR/issued/cp-$kind.crt" -noout -subject 2>/dev/null)"
	case "$s" in
		*"CN=system:$kind:cp"*"O=system:${kind}s"*) ok "$kind: CN=system:$kind:cp, O=system:${kind}s" ;;
		*) bad "$kind: falsches Subjekt" "$s" ;;
	esac
done

# --- serving: SANs und beide EKU --------------------------------------------
mkcsr serving "egal"
"$CA" --dir "$DIR" --sign-csr "$T/serving.csr" --kind serving --name meister-box \
	--san "meister-box,10.0.0.10" >/dev/null 2>&1
crt="$DIR/issued/meister-box-serving.crt"
s="$(openssl x509 -in "$crt" -noout -subject 2>/dev/null)"
case "$s" in
	*"CN=meister-box"*"O=system:controllers"*) ok "serving: CN=<host>, O=system:controllers" ;;
	*) bad "serving: falsches Subjekt" "$s" ;;
esac
san="$(openssl x509 -in "$crt" -noout -ext subjectAltName 2>/dev/null)"
for want in "DNS:meister-box" "IP Address:10.0.0.10" "DNS:localhost" "IP Address:127.0.0.1"; do
	case "$san" in
		*"$want"*) ok "serving: SAN $want" ;;
		*) bad "serving: SAN $want fehlt" "$san" ;;
	esac
done
eku="$(openssl x509 -in "$crt" -noout -ext extendedKeyUsage 2>/dev/null)"
case "$eku" in
	*"TLS Web Server Authentication"*"TLS Web Client Authentication"*) ok "serving: serverAuth und clientAuth" ;;
	*) bad "serving: EKU falsch" "$eku" ;;
esac

# --- was abgelehnt wird -----------------------------------------------------
# Eine Anfrage, deren Signatur nicht aufgeht, ist keine Anfrage: sonst koennte
# jemand den oeffentlichen Schluessel eines anderen unter eigenem Namen
# einreichen und sich fuer einen Schluessel verbuergen lassen, den er nicht hat.
sed 's/^\(.\{20\}\)A/\1B/; s/^\(.\{20\}\)B/\1A/' "$T/node.csr" > "$T/tampered.csr"
if "$CA" --dir "$DIR" --sign-csr "$T/tampered.csr" --kind node --name evil >/dev/null 2>&1; then
	bad "eine verfaelschte Anfrage wurde signiert"
else
	ok "eine Anfrage ohne gueltige Signatur wird abgelehnt"
fi
[ -f "$DIR/issued/evil-node.crt" ] && bad "und trotzdem liegt ein Zertifikat da" || ok "und es liegt keins da"

if "$CA" --dir "$DIR" --sign-csr "$T/node.csr" --name n1 >/dev/null 2>&1; then
	bad "--sign-csr ohne --kind wurde akzeptiert"
else
	ok "--sign-csr ohne --kind wird abgelehnt"
fi
if "$CA" --dir "$DIR" --sign-csr "$T/node.csr" --kind node >/dev/null 2>&1; then
	bad "--sign-csr ohne --name wurde akzeptiert"
else
	ok "--sign-csr ohne --name wird abgelehnt"
fi
if "$CA" --dir "$DIR" --sign-csr "$T/node.csr" --kind node --name n1 --san a >/dev/null 2>&1; then
	bad "--san bei einem Client-Zertifikat wurde akzeptiert"
else
	ok "--san bei einem Client-Zertifikat wird abgelehnt"
fi
if "$CA" --dir "$DIR" --sign-csr "$T/nicht-da.csr" --kind node --name n1 >/dev/null 2>&1; then
	bad "eine nicht vorhandene Anfrage wurde signiert"
else
	ok "eine nicht vorhandene Anfrage wird abgelehnt"
fi

# --- additiv ----------------------------------------------------------------
# Was M5A braucht: jedes ausgestellte Zertifikat bleibt liegen, damit
# `--index-rebuild` es einliest (M0 S9).
count="$(find "$DIR/issued" -name '*.crt' | wc -l)"
mkcsr node2 "egal"
"$CA" --dir "$DIR" --sign-csr "$T/node2.csr" --kind node --name n2 >/dev/null 2>&1
after="$(find "$DIR/issued" -name '*.crt' | wc -l)"
if [ "$after" -eq "$((count + 1))" ]; then
	ok "eine weitere Ausstellung nimmt keine vorherige weg ($count -> $after)"
else
	bad "die Ablage ist nicht additiv" "$count -> $after"
fi

# --- die alten Pfade leben weiter -------------------------------------------
"$CA" --dir "$DIR" --node alt --serving alt-host:10.0.0.9 >/dev/null 2>&1
if [ -f "$DIR/system-node-alt.key" ] && [ -f "$DIR/system-node-alt.crt" ] && [ -f "$DIR/alt-host.crt" ]; then
	ok "der Schluessel-und-Zertifikat-Weg (--node/--serving) ist unveraendert"
else
	bad "der alte Weg ist kaputt"
fi

printf '\n%d ok, %d FAIL\n' "$pass" "$fail"
[ "$fail" -eq 0 ]

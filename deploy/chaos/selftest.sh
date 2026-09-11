#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR
#
# deploy/chaos/selftest.sh — does the harness still reach a control plane?
#
# WHY THIS EXISTS. The harness was written against a lab whose REST ports were
# plain http. Image 58 turned mTLS on, and from that moment every request it
# made died at the first byte:
#
#     ApiError HTTP 0: BadStatusLine:  2
#
# That is TLS answering an http client. Nothing in the harness said so — the
# first hour of the mini-chaos run went into reading an exception. A tool
# whose whole job is to notice things has to notice that it is talking to a
# wall, and it has to notice it without twelve hosts.
#
# So: a throwaway CA, an etcd, both controller tiers on loopback with mTLS
# exactly as the fleet runs it, and `mini.py M0` against them. M0 asks every
# endpoint for its discovery document and judges the ANSWER — came back at
# all, is this API's document, calls itself the tier we think it is. If the
# transport is broken, M0 says "the harness cannot speak to this endpoint at
# all" instead of blaming the control plane.
#
#     ./selftest.sh                 build, run, tear down
#     KEEP=1 ./selftest.sh          leave the stack up to poke at
#
# Needs: cargo (or prebuilt binaries), etcd, openssl, python3. No root, no
# network, no lab. Everything lives under $ROOT and is removed at the end.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
ROOT="${CHAOS_SELFTEST_ROOT:-/tmp/ms-chaos-controller}"

# Ports nothing else in this repo uses. The lab is 3000/3001 and
# 50050/50051; the struktur round's local stack was 3700/3701. A self-test
# that collided with a stack somebody left running would fail for a reason
# that has nothing to do with what it checks.
CLOUD_PORT=3800
CLUSTER_PORT=3801
CLOUD_SESSION=50850
CLUSTER_SESSION=50851
ETCD_CLIENT=23790
ETCD_PEER=23791

pass=0
fail=0
ok()  { printf '  ok   %s\n' "$1"; pass=$((pass + 1)); }
bad() { printf '  FAIL %s\n' "$1"; shift; for l in "$@"; do printf '       %s\n' "$l"; done; fail=$((fail + 1)); }

PIDS=()
cleanup() {
    [ "${KEEP:-0}" = 1 ] && { echo "KEEP=1: the stack stays up under $ROOT"; return; }
    for pid in "${PIDS[@]:-}"; do
        [ -n "$pid" ] && kill "$pid" 2>/dev/null
    done
    # Give them a moment to let go of the ports before the next run.
    sleep 0.5
    for pid in "${PIDS[@]:-}"; do
        [ -n "$pid" ] && kill -9 "$pid" 2>/dev/null
    done
    rm -rf "$ROOT"
}
trap cleanup EXIT

for tool in etcd openssl python3; do
    command -v "$tool" >/dev/null || { echo "selftest: no $tool in PATH"; exit 1; }
done

rm -rf "$ROOT"
mkdir -p "$ROOT"/{pki,etcd,log}

echo
echo "A. a throwaway CA, from the tool the lab uses"

# The SAME script that issues the fleet's certificates, so a change in the
# identity model breaks this test rather than passing it. `--admin root` is
# the break-glass identity `mtls.py` presents; the cloud and cluster entries
# give both a serving certificate and the system identity each tier shows the
# other.
if "$REPO/tools/meister-ca" --dir "$ROOT/pki" \
       --cloud selftest-cloud:127.0.0.1 \
       --cluster cluster-1:127.0.0.1 \
       --admin root >"$ROOT/log/ca.log" 2>&1; then
    ok "meister-ca issued a cloud, a cluster and a break-glass identity"
else
    bad "meister-ca" "$(tail -5 "$ROOT/log/ca.log")"
    exit 1
fi

echo
echo "B. the binaries"

CLOUD_BIN="${MEISTER_CLOUD_BIN:-$REPO/target/debug/meister-cloud-controller}"
CLUSTER_BIN="${MEISTER_CLUSTER_BIN:-$REPO/target/debug/meister-cluster-controller}"
if [ ! -x "$CLOUD_BIN" ] || [ ! -x "$CLUSTER_BIN" ]; then
    echo "  building (cargo build -p meister-cloud-controller -p meister-cluster-controller)"
    (cd "$REPO" && cargo build -p meister-cloud-controller -p meister-cluster-controller) \
        >"$ROOT/log/build.log" 2>&1 || { bad "cargo build" "$(tail -20 "$ROOT/log/build.log")"; exit 1; }
fi
[ -x "$CLOUD_BIN" ] && [ -x "$CLUSTER_BIN" ] \
    && ok "both controller binaries are there" \
    || { bad "the controller binaries" "$CLOUD_BIN / $CLUSTER_BIN"; exit 1; }

echo
echo "C. etcd, and both tiers with mTLS on"

etcd --data-dir "$ROOT/etcd" \
     --listen-client-urls "http://127.0.0.1:$ETCD_CLIENT" \
     --advertise-client-urls "http://127.0.0.1:$ETCD_CLIENT" \
     --listen-peer-urls "http://127.0.0.1:$ETCD_PEER" \
     --initial-advertise-peer-urls "http://127.0.0.1:$ETCD_PEER" \
     --initial-cluster "default=http://127.0.0.1:$ETCD_PEER" \
     --name default >"$ROOT/log/etcd.log" 2>&1 &
PIDS+=($!)

for _ in $(seq 1 50); do
    etcdctl --endpoints "http://127.0.0.1:$ETCD_CLIENT" endpoint health >/dev/null 2>&1 && break
    sleep 0.2
done
if etcdctl --endpoints "http://127.0.0.1:$ETCD_CLIENT" endpoint health >/dev/null 2>&1; then
    ok "etcd is up on $ETCD_CLIENT"
else
    bad "etcd never became healthy" "$(tail -5 "$ROOT/log/etcd.log")"
    exit 1
fi

# The two configs, with the same three keys the fleet's have: a serving pair
# and the CA client certificates chain to. `chain = ["mtls"]` at both tiers
# — the cloud's second link is oidc, which needs a provider and is not what
# this test is about.
cat >"$ROOT/cloud.toml" <<EOF
cloud_name = "selftest"
listen_api = "127.0.0.1:$CLOUD_PORT"
listen_session = "127.0.0.1:$CLOUD_SESSION"
etcd_endpoints = "http://127.0.0.1:$ETCD_CLIENT"
etcd_prefix = "/cloud"
tls_cert = "$ROOT/pki/selftest-cloud.crt"
tls_key = "$ROOT/pki/selftest-cloud.key"
client_ca = "$ROOT/pki/ca.crt"
identity_cert = "$ROOT/pki/system-cloud-selftest-cloud.crt"
identity_key = "$ROOT/pki/system-cloud-selftest-cloud.key"
[auth]
chain = ["mtls"]
EOF

cat >"$ROOT/cluster.toml" <<EOF
cluster_name = "cluster-1"
listen_api = "127.0.0.1:$CLUSTER_PORT"
listen_session = "127.0.0.1:$CLUSTER_SESSION"
etcd_endpoints = "http://127.0.0.1:$ETCD_CLIENT"
etcd_prefix = "/cluster"
cloud_addr = "127.0.0.1:$CLOUD_SESSION"
tls_cert = "$ROOT/pki/cluster-1.crt"
tls_key = "$ROOT/pki/cluster-1.key"
client_ca = "$ROOT/pki/ca.crt"
cloud_ca = "$ROOT/pki/ca.crt"
cloud_cert = "$ROOT/pki/system-cluster-cluster-1.crt"
cloud_key = "$ROOT/pki/system-cluster-cluster-1.key"
[auth]
chain = ["mtls"]
EOF

# The identity files meister-ca writes are named after the CN. Find them
# rather than guessing: a rename in the CA script has to break this loudly
# and not silently produce a tier with no identity (which is D2 all over).
find_identity() {
    local want=$1 out
    out="$(ls "$ROOT/pki/" | grep -F "$want" | grep '\.crt$' | head -1)"
    [ -n "$out" ] && printf '%s\n' "${out%.crt}"
}
cloud_id="$(find_identity 'system:cloud:selftest-cloud')"
cluster_id="$(find_identity 'system:cluster:cluster-1')"
if [ -n "$cloud_id" ]; then
    sed -i "s|identity_cert = .*|identity_cert = \"$ROOT/pki/$cloud_id.crt\"|; \
            s|identity_key = .*|identity_key = \"$ROOT/pki/$cloud_id.key\"|" "$ROOT/cloud.toml"
fi
if [ -n "$cluster_id" ]; then
    sed -i "s|cloud_cert = .*|cloud_cert = \"$ROOT/pki/$cluster_id.crt\"|; \
            s|cloud_key = .*|cloud_key = \"$ROOT/pki/$cluster_id.key\"|" "$ROOT/cluster.toml"
fi

RUST_LOG=warn "$CLOUD_BIN" --config "$ROOT/cloud.toml" >"$ROOT/log/cloud.log" 2>&1 &
PIDS+=($!)
RUST_LOG=warn "$CLUSTER_BIN" --config "$ROOT/cluster.toml" >"$ROOT/log/cluster.log" 2>&1 &
PIDS+=($!)

# Wait on the SOCKET and not on a sleep: a fixed sleep is either too short on
# a loaded machine or wasted on an idle one, and this test runs in a loop.
wait_port() {
    local port=$1
    for _ in $(seq 1 100); do
        (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null && { exec 3<&- 3>&-; return 0; }
        sleep 0.1
    done
    return 1
}
wait_port "$CLOUD_PORT"   && ok "the cloud serves on $CLOUD_PORT"   || bad "the cloud never listened" "$(tail -10 "$ROOT/log/cloud.log")"
wait_port "$CLUSTER_PORT" && ok "the cluster serves on $CLUSTER_PORT" || bad "the cluster never listened" "$(tail -10 "$ROOT/log/cluster.log")"
[ "$fail" -gt 0 ] && exit 1

echo
echo "D. the wall this test exists for: http against a tls port"

# Proof that the port really is mTLS. Without it a green M0 could mean the
# transport works OR that the tier is serving plain http and the harness
# happens to speak it — the exact ambiguity Image 58 created.
plain="$(CHAOS_DIR="$HERE" CHAOS_SCHEME=http CHAOS_CLOUD=127.0.0.1 \
         CHAOS_CLOUD_PORT=$CLOUD_PORT CHAOS_OUT="$ROOT/out" \
         python3 - <<'PY' 2>&1
import os, sys
sys.path.insert(0, os.environ["CHAOS_DIR"])
import ops
try:
    print("HTTP", ops.cloud("GET", "")[0])
except ops.ApiError as e:
    # Printable only: what TLS answers an http client with is the first
    # bytes of a record, and a raw NUL in a command substitution is a
    # warning from bash rather than an answer from this test.
    print("WALL", "".join(c if c.isprintable() else "." for c in str(e)))
PY
)"
case "$plain" in
    WALL*) ok "an http client meets a wall here (${plain:0:60}...)" ;;
    *)     bad "the port is not tls at all" "$plain" ;;
esac

echo
echo "E. the harness, over the transport the tiers speak"

out="$ROOT/log/m0.txt"
CHAOS_PKI_DIR="$ROOT/pki" \
CHAOS_CA="$ROOT/pki/ca.crt" \
CHAOS_CERT="$ROOT/pki/root.crt" \
CHAOS_KEY="$ROOT/pki/root.key" \
CHAOS_CLOUD=127.0.0.1 \
CHAOS_CLUSTER1=127.0.0.1 \
CHAOS_CLUSTER2= \
CHAOS_CLOUD_PORT="$CLOUD_PORT" \
CHAOS_CLUSTER_PORT="$CLUSTER_PORT" \
CHAOS_OUT="$ROOT/out" \
    python3 "$HERE/mini.py" M0 >"$out" 2>&1
rc=$?
sed 's/^/       /' "$out"
if [ "$rc" = 0 ]; then
    ok "mini.py M0: every tier answered, and said what it is"
else
    bad "mini.py M0 found something (exit $rc)" "see $out"
fi
grep -q '"scheme": "https"' "$out" \
    && ok "and it did it over https, not by falling back to plain http" \
    || bad "the harness did not use tls" "the CHAOS_CA/CERT/KEY it was given did not take"

echo
echo "F. the security statement S13 makes is a measurement (D-H1)"

# `scenarios.py` used to APPEND "the cloud REST edge answers unauthenticated
# plaintext HTTP" unconditionally, without looking at the number it printed
# beside it -- and went on saying it five images after mTLS was turned on.
# `mtls.probe` is what replaced the constant, and this is the one place its
# three answers can be checked against an edge whose configuration is known:
# this stack runs `chain = ["mtls"]`, exactly as the fleet does.
probe="$ROOT/log/probe.json"
CHAOS_CA="$ROOT/pki/ca.crt" \
CHAOS_CERT="$ROOT/pki/root.crt" \
CHAOS_KEY="$ROOT/pki/root.key" \
    python3 "$HERE/mtls.py" 127.0.0.1 "$CLOUD_PORT" >"$probe" 2>&1
read -r got < "$probe"
want='{"full": 200, "http": 0, "naked": 401}'
if [ "$got" = "$want" ]; then
    ok "http -> 0, https without a client cert -> 401, with one -> 200"
else
    bad "the edge did not answer the three questions the way it is configured to" \
        "expected $want" "got      $got"
fi
echo
echo "==> $pass ok, $fail FAIL"
[ "$fail" = 0 ]

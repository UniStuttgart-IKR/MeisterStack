#!/usr/bin/env python3
"""fuzz.py — adversarial input against both tiers, with oracles.

    ./fuzz.py --mode api        --seed 5001 --rounds 200
    ./fuzz.py --mode names      --seed 5002
    ./fuzz.py --mode isolation  --seed 5003
    ./fuzz.py --mode lifecycle  --seed 5004 --rounds 60
    ./fuzz.py --mode concurrency --seed 5005 --rounds 30
    ./fuzz.py --mode all --seed 5000

Random input is only worth the tokens if something can say what a bug *is*.
These are the oracles; everything else is noise and gets dropped:

  F-5XX        any 5xx. A malformed request must be a 4xx. A 500 is the server
               failing on its own input, and it is always a defect.
  F-ACCEPTED   a 2xx where the rules say refuse (cross-tenant reference, a name
               that is not a DNS label, a value over quota).
  F-REFUSED    a 4xx where the rules say accept -- the boundary cases that are
               *legal* and get rejected anyway.
  F-SLOW       a single request over --slow seconds. A hang is a defect even
               when the answer is eventually right.
  F-LEAK       an error body carrying a panic, an unwrap, a source path or a
               backtrace. That is an internal detail on an external surface.
  F-PANIC      a controller unit whose NRestarts went up during the run. The
               request that did it is the one before the counter moved.
  F-INVARIANT  invariants.py broke after a batch.

Every finding carries the seed and an exact curl line, because a finding
without a reproduction is an anecdote.
"""

import argparse
import json
import random
import re
import string
import subprocess
import time
import urllib.error
import urllib.request

import mtls
import ops
from ops import log

CA = "/mnt/vmstore/MeisterStack/labpki/ca.crt"
CERT = "/mnt/vmstore/MeisterStack/labpki/root.crt"
KEY = "/mnt/vmstore/MeisterStack/labpki/root.key"

LEAK = re.compile(r"panic|unwrap\(\)|/nix/store|src/[a-z_/]+\.rs|backtrace|thread '|"
                  r"RUST_BACKTRACE|etcdserver:|mvcc:", re.I)

TENANT_A, TENANT_B = "fuzz-a", "fuzz-b"
FOUND = []


# --- the wire ---------------------------------------------------------------

def raw(tier, method, path, body=None, timeout=20, ctype="application/json"):
    """Like ops.call, but the body may be anything at all -- including bytes
    that are not JSON. Returns (code, text, seconds)."""
    ip, port = (ops.CLOUD[0], ops.CLOUD_PORT) if tier == "cloud" else \
               (ops.CLUSTER1[0], ops.CLUSTER_PORT)
    url = f"{mtls.scheme()}://{ip}:{port}{ops.V1}{path}"
    data = body if isinstance(body, (bytes, type(None))) else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", ctype)
    t0 = time.time()
    try:
        with mtls.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace"), time.time() - t0
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), time.time() - t0
    except Exception as e:
        return 0, f"{type(e).__name__}: {e}", time.time() - t0


def curl_line(tier, method, path, body):
    ip, port = (ops.CLOUD[0], ops.CLOUD_PORT) if tier == "cloud" else \
               (ops.CLUSTER1[0], ops.CLUSTER_PORT)
    b = ""
    if body is not None:
        text = body.decode("utf-8", "replace") if isinstance(body, bytes) else json.dumps(body)
        b = f" -H 'Content-Type: application/json' -d {json.dumps(text[:400])}"
    return (f"curl -sk --cacert {CA} --cert {CERT} --key {KEY} "
            f"-X {method}{b} 'https://{ip}:{port}{ops.V1}{path}'")


def unit_restarts():
    out = {}
    for ip in ops.CLOUD:
        out[ip] = ops.ctl(ip, "systemctl show -p NRestarts --value meister-cloud-controller")[1].strip()
    for ip in list(ops.CLUSTER1) + list(ops.CLUSTER2):
        out[ip] = ops.ctl(ip, "systemctl show -p NRestarts --value meister-cluster-controller")[1].strip()
    return out


# --- the oracles ------------------------------------------------------------

def judge(seed, tag, tier, method, path, body, expect, slow):
    code, text, secs = raw(tier, method, path, body)
    hits = []
    if code >= 500:
        hits.append(("F-5XX", f"{code} on {method} {path}: {text[:160]}"))
    elif code == 0 and "timed out" in text.lower():
        hits.append(("F-SLOW", f"transport timeout on {method} {path}"))
    if secs > slow and code:
        hits.append(("F-SLOW", f"{secs:.1f}s for {method} {path} (limit {slow}s)"))
    if LEAK.search(text or ""):
        hits.append(("F-LEAK", f"{method} {path} leaked internals: "
                               f"{LEAK.search(text).group(0)} in {text[:200]}"))
    if expect == "refuse" and 200 <= code < 300:
        hits.append(("F-ACCEPTED", f"{method} {path} accepted what should be refused: {tag}"))
    if expect == "accept" and 400 <= code < 500:
        hits.append(("F-REFUSED", f"{method} {path} refused a legal value ({code}): {tag}"))
    for fid, msg in hits:
        ops.finding(fid, tag, seed, msg)
        FOUND.append({"id": fid, "tag": tag, "seed": seed, "msg": msg,
                      "repro": curl_line(tier, method, path, body)})
    return code, text, secs


# --- payloads ---------------------------------------------------------------

def hostile_values(rng):
    big = "A" * 100_000
    deep = {"a": None}
    node = deep
    for _ in range(200):
        node["a"] = {"a": None}
        node = node["a"]
    return [
        ("empty-string", ""), ("null", None), ("huge-string", big),
        ("nul-byte", "a\x00b"), ("newlines", "a\nb\rc"),
        ("unicode", "ﬀ𝕍𝕄–ü—🙂"), ("rtl-override", "a‮b"),
        ("path-traversal", "../../etc/shadow"), ("slash", "a/b"),
        ("json-in-string", '{"kind":"Vm"}'), ("brace", "${jndi:ldap://x}"),
        ("neg-int", -1), ("zero", 0), ("i64-max", 2**63 - 1),
        ("i64-overflow", 2**63), ("u64-overflow", 2**64 + 7),
        ("float", 1.5), ("bool", True), ("list", [1, 2, 3]),
        ("dict", {"x": 1}), ("deep-nest", deep),
        ("spaces", "   "), ("dash", "-"), ("dots", "..."),
    ]


def malformed_bodies():
    return [
        ("not-json", b"this is not json"),
        ("truncated", b'{"apiVersion":"meister.io/v1","kind":"Vm"'),
        ("empty-body", b""),
        ("array-not-object", b'[1,2,3]'),
        ("json-null", b'null'),
        ("huge-json", b'{"a":"' + b"B" * 2_000_000 + b'"}'),
        ("dup-keys", b'{"kind":"Vm","kind":"Tenant","metadata":{"name":"dup"},"spec":{}}'),
        ("wrong-apiversion", {"apiVersion": "meister.io/v99", "kind": "Vm",
                              "metadata": {"name": "fz-apiver"}, "spec": {}}),
        ("no-kind", {"apiVersion": "meister.io/v1",
                     "metadata": {"name": "fz-nokind"}, "spec": {}}),
        ("kind-mismatch", {"apiVersion": "meister.io/v1", "kind": "Tenant",
                           "metadata": {"name": "fz-mismatch"}, "spec": {}}),
        ("no-metadata", {"apiVersion": "meister.io/v1", "kind": "Vm", "spec": {}}),
        ("status-injected", {"apiVersion": "meister.io/v1", "kind": "Vm",
                             "metadata": {"name": "fz-status"},
                             "spec": {"vcpus": 1, "memMib": 256},
                             "status": {"phase": "Running", "nodeName": "agent-1a"}}),
    ]


# DNS label rules: <=63 chars, [a-z0-9] with inner hyphens. The API says it
# enforces them ("Namen sind DNS-Labels"), so each of these has a right answer.
NAMES = [
    ("ok-simple", "fz-ok-1", "accept"),
    ("ok-63", "f" + "z" * 62, "accept"),
    ("ok-digits", "fz-123", "accept"),
    ("too-long-64", "f" + "z" * 63, "refuse"),
    ("too-long-254", "f" * 254, "refuse"),
    ("uppercase", "FZ-Upper", "refuse"),
    ("leading-hyphen", "-fz", "refuse"),
    ("trailing-hyphen", "fz-", "refuse"),
    ("underscore", "fz_under", "refuse"),
    ("dot", "fz.dotted", "refuse"),
    ("empty", "", "refuse"),
    ("space", "fz name", "refuse"),
    ("slash", "fz/slash", "refuse"),
    ("dotdot", "..", "refuse"),
    ("unicode", "fz-ü", "refuse"),
    ("nul", "fz\x00x", "refuse"),
    ("newline", "fz\nx", "refuse"),
    ("homoglyph", "fz-а", "refuse"),   # cyrillic a
    ("only-digits", "12345", "accept"),
]


# --- modes ------------------------------------------------------------------

def ensure(tenant):
    c, _ = ops.cloud("GET", f"/tenants/{tenant}")
    if c == 404:
        ops.cloud("POST", "/tenants", ops.obj("Tenant", tenant, {"description": "fuzz"}))


def mode_names(seed, rng, slow):
    log("=== fuzz names: the DNS-label boundary ===")
    ensure(TENANT_A)
    for tag, name, expect in NAMES:
        body = {"apiVersion": "meister.io/v1", "kind": "Vm",
                "metadata": {"name": name, "tenant": TENANT_A},
                "spec": {"vcpus": 1, "memMib": 256, "image": "tiny"}}
        code, text, _ = judge(seed, f"name:{tag}", "cloud", "POST", "/vms", body, expect, slow)
        if 200 <= code < 300:
            ops.cloud("DELETE", f"/vms/{name}")
        log(f"  name {tag:18s} -> {code} (want {expect})")


def mode_api(seed, rng, slow, rounds):
    log("=== fuzz api: hostile payloads on every writable kind ===")
    ensure(TENANT_A)
    for tag, body in malformed_bodies():
        judge(seed, f"body:{tag}", "cloud", "POST", "/vms", body, "refuse", slow)
        log(f"  body {tag}")
    kinds = [("/vms", "Vm", {"vcpus": 1, "memMib": 256}),
             ("/volumes", "Volume", {"sizeGib": 1, "pool": "fabric"}),
             ("/tenants", "Tenant", {"description": "x"}),
             ("/floatingpools", "FloatingPool", {"network": "ext"}),
             ("/routers", "Router", {"network": "ext"}),
             ("/images", "Image", {"url": "http://example.invalid/x.img"}),
             ("/secrets", "Secret", {"data": {"k": "dg=="}}),
             ("/users", "User", {"tenant": TENANT_A, "role": "viewer"})]
    vals = hostile_values(rng)
    for i in range(rounds):
        path, kind, base = rng.choice(kinds)
        spec = dict(base)
        field = rng.choice(list(spec) or ["x"])
        vtag, val = rng.choice(vals)
        spec[field] = val
        name = f"fz-{seed}-{i:03d}"
        body = {"apiVersion": "meister.io/v1", "kind": kind,
                "metadata": {"name": name, "tenant": TENANT_A}, "spec": spec}
        code, _, _ = judge(seed, f"{kind}.{field}={vtag}", "cloud", "POST", path,
                           body, "any", slow)
        if 200 <= code < 300:
            ops.cloud("DELETE", f"{path}/{name}")
        if i % 25 == 24:
            log(f"  api round {i+1}/{rounds}, findings so far {len(FOUND)}")


def mode_isolation(seed, rng, slow):
    log("=== fuzz isolation: does a tenant boundary hold under a direct push ===")
    ensure(TENANT_A)
    ensure(TENANT_B)
    vol = f"fz-iso-vol-{seed}"
    ops.cloud("POST", "/volumes", {"apiVersion": "meister.io/v1", "kind": "Volume",
              "metadata": {"name": vol, "tenant": TENANT_B},
              "spec": {"sizeGib": 1, "pool": "fabric"}})
    cases = [
        ("vm-in-a-mounts-volume-of-b", "POST", "/vms",
         {"apiVersion": "meister.io/v1", "kind": "Vm",
          "metadata": {"name": f"fz-iso-{seed}", "tenant": TENANT_A},
          "spec": {"vcpus": 1, "memMib": 256, "volumes": [{"name": vol}]}}, "refuse"),
        ("read-b-volume-as-a", "GET", f"/volumes/{vol}?tenant={TENANT_A}", None, "any"),
        ("delete-b-volume-via-a", "DELETE", f"/volumes/{vol}?tenant={TENANT_A}", None, "refuse"),
        ("vm-with-foreign-tenant-in-body", "POST", "/vms",
         {"apiVersion": "meister.io/v1", "kind": "Vm",
          "metadata": {"name": f"fz-iso2-{seed}", "tenant": "does-not-exist"},
          "spec": {"vcpus": 1, "memMib": 256}}, "refuse"),
        ("negative-quota-tenant", "POST", "/tenants",
         {"apiVersion": "meister.io/v1", "kind": "Tenant",
          "metadata": {"name": f"fz-negq-{seed}"},
          "spec": {"description": "x", "quota": {"vcpus": -5, "memMib": -1}}}, "refuse"),
        ("csr-for-a-node-identity", "POST", "/certificatesigningrequests",
         {"apiVersion": "meister.io/v1", "kind": "CertificateSigningRequest",
          "metadata": {"name": f"fz-csr-{seed}"},
          "spec": {"request": "bm90LWEtY3Ny", "usages": ["client auth"],
                   "commonName": "agent-1a"}}, "refuse"),
    ]
    for tag, method, path, body, expect in cases:
        code, text, _ = judge(seed, f"iso:{tag}", "cloud", method, path, body, expect, slow)
        log(f"  iso {tag:34s} -> {code} (want {expect})")
    ops.cloud("DELETE", f"/volumes/{vol}")


def mode_authz(seed, rng, slow):
    """The surfaces where a capability is handed out, and where a secret rests.

    A console ticket is a bearer capability for somebody else's screen, and a
    Secret is the one kind whose whole point is that reading it back should not
    be free. Both are tenant-scoped per the discovery document; this asks the
    server to prove it rather than taking the field's word for it.
    """
    log("=== fuzz authz: console tickets and secrets across a tenant line ===")
    ensure(TENANT_A)
    ensure(TENANT_B)
    vm = f"fz-authz-{seed}"
    c, _ = ops.cloud("POST", "/vms", {"apiVersion": "meister.io/v1", "kind": "Vm",
           "metadata": {"name": vm, "tenant": TENANT_B},
           "spec": {"vcpus": 1, "memMib": 256}})
    log(f"  a VM in {TENANT_B} to aim at: {c}")

    sec = f"fz-secret-{seed}"
    ops.cloud("POST", "/secrets", {"apiVersion": "meister.io/v1", "kind": "Secret",
              "metadata": {"name": sec, "tenant": TENANT_B},
              "spec": {"data": {"password": "c3VwZXItc2VjcmV0"}}})

    cases = [
        ("ticket-for-foreign-vm", "POST", f"/vms/{vm}/console/ticket?tenant={TENANT_A}",
         {}, "refuse"),
        ("ticket-no-tenant", "POST", f"/vms/{vm}/console/ticket", {}, "any"),
        ("logs-of-foreign-vm", "GET", f"/vms/{vm}/logs?tenant={TENANT_A}", None, "refuse"),
        ("events-of-foreign-vm", "GET", f"/vms/{vm}/events?tenant={TENANT_A}", None, "refuse"),
        ("read-foreign-secret", "GET", f"/secrets/{sec}?tenant={TENANT_A}", None, "refuse"),
        ("list-secrets-all-tenants", "GET", "/secrets", None, "any"),
        ("patch-own-status", "PATCH", f"/vms/{vm}?tenant={TENANT_B}",
         {"status": {"phase": "Running", "nodeName": "agent-1a"}}, "refuse"),
        ("delete-foreign-vm", "DELETE", f"/vms/{vm}?tenant={TENANT_A}", None, "refuse"),
    ]
    for tag, method, path, body, expect in cases:
        code, text, _ = judge(seed, f"authz:{tag}", "cloud", method, path, body, expect, slow)
        log(f"  authz {tag:26s} -> {code} (want {expect})")
        # A secret that comes back with its value in the clear is its own finding,
        # whichever tenant asked.
        if "secret" in tag and 200 <= code < 300 and "c3VwZXItc2VjcmV0" in (text or ""):
            ops.finding("F-SECRET", f"authz:{tag}", seed,
                        f"{method} {path} returned the secret value in the body")
            FOUND.append({"id": "F-SECRET", "tag": tag, "seed": seed,
                          "msg": "secret value readable over the API",
                          "repro": curl_line("cloud", method, path, body)})

    # And does the value ever reach a log?
    for ip in ops.CLOUD:
        rc, out = ops.ctl(ip, "journalctl -u meister-cloud-controller --since '-5 min' "
                              "--no-pager 2>/dev/null | grep -c 'c3VwZXItc2VjcmV0' || true")
        if out.strip().isdigit() and int(out.strip()) > 0:
            ops.finding("F-SECRET", "authz:secret-in-journal", seed,
                        f"the secret value appears {out.strip()}x in the journal on {ip}")
            FOUND.append({"id": "F-SECRET", "tag": "secret-in-journal", "seed": seed,
                          "msg": f"{ip}: {out.strip()} hits", "repro": "-"})

    ops.cloud("DELETE", f"/secrets/{sec}")
    ops.cloud("DELETE", f"/vms/{vm}")


def mode_lifecycle(seed, rng, slow, rounds):
    """Random *legal* transition sequences. Every step is something a user may
    do; the bug is the order, not the call."""
    log("=== fuzz lifecycle: legal calls in orders nobody tried ===")
    ensure(TENANT_A)
    name = f"fz-life-{seed}"
    verbs = ["create", "stop", "start", "delete", "get", "patch-labels", "recreate"]
    for i in range(rounds):
        v = rng.choice(verbs)
        if v == "create" or v == "recreate":
            body = {"apiVersion": "meister.io/v1", "kind": "Vm",
                    "metadata": {"name": name, "tenant": TENANT_A},
                    "spec": {"vcpus": 1, "memMib": 256}}
            judge(seed, f"life:{v}", "cloud", "POST", "/vms", body, "any", slow)
        elif v in ("stop", "start"):
            judge(seed, f"life:{v}", "cloud", "PATCH", f"/vms/{name}",
                  {"spec": {"running": v == "start"}}, "any", slow)
        elif v == "delete":
            judge(seed, "life:delete", "cloud", "DELETE", f"/vms/{name}", None, "any", slow)
        elif v == "patch-labels":
            judge(seed, "life:patch", "cloud", "PATCH", f"/vms/{name}",
                  {"metadata": {"labels": {f"k{i}": "v"}}}, "any", slow)
        else:
            judge(seed, "life:get", "cloud", "GET", f"/vms/{name}", None, "any", slow)
        if i % 15 == 14:
            rc = subprocess.call(["./invariants.py", "--quiet", "--tag", f"fuzz-life-{seed}",
                                  "--seed", str(seed)], cwd=ops.os.path.dirname(
                                      ops.os.path.abspath(__file__)))
            if rc != 0:
                ops.finding("F-INVARIANT", "life", seed,
                            f"invariants broke after lifecycle step {i}")
                FOUND.append({"id": "F-INVARIANT", "tag": "life", "seed": seed,
                              "msg": f"step {i}", "repro": f"fuzz.py --mode lifecycle --seed {seed}"})
            log(f"  lifecycle {i+1}/{rounds}, invariants {'ok' if rc == 0 else 'BROKEN'}")
    ops.cloud("DELETE", f"/vms/{name}")


def mode_concurrency(seed, rng, slow, rounds):
    """The same object, written from several replicas at once."""
    log("=== fuzz concurrency: racing writes across replicas ===")
    ensure(TENANT_A)
    import threading
    for i in range(rounds):
        name = f"fz-race-{seed}-{i:02d}"
        body = {"apiVersion": "meister.io/v1", "kind": "Vm",
                "metadata": {"name": name, "tenant": TENANT_A},
                "spec": {"vcpus": 1, "memMib": 256}}
        codes = []
        lock = threading.Lock()

        def shoot(ip):
            c, _ = ops.call(ip, ops.CLOUD_PORT, "POST", ops.V1 + "/vms", body)
            with lock:
                codes.append((ip, c))

        ts = [threading.Thread(target=shoot, args=(ip,)) for ip in ops.CLOUD]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        ok = [c for _, c in codes if 200 <= c < 300]
        if len(ok) > 1:
            ops.finding("F-ACCEPTED", "race:create", seed,
                        f"the same name was created {len(ok)} times at once: {codes}")
            FOUND.append({"id": "F-ACCEPTED", "tag": "race:create", "seed": seed,
                          "msg": f"{len(ok)} creates won for {name}", "repro": f"fuzz.py --mode concurrency --seed {seed}"})
        for _, c in codes:
            if c >= 500:
                ops.finding("F-5XX", "race:create", seed, f"{c} racing creates: {codes}")
        ops.cloud("DELETE", f"/vms/{name}")
        if i % 10 == 9:
            log(f"  race {i+1}/{rounds}, findings {len(FOUND)}")


# --- main -------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", required=True,
                    choices=["api", "names", "isolation", "authz", "lifecycle", "concurrency", "all"])
    ap.add_argument("--seed", type=int, required=True)
    ap.add_argument("--rounds", type=int, default=120)
    ap.add_argument("--slow", type=float, default=10.0)
    a = ap.parse_args()
    rng = random.Random(a.seed)

    before = unit_restarts()
    log(f"=== fuzz {a.mode} seed={a.seed} restarts-before={before} ===")
    modes = ["names", "api", "isolation", "authz", "lifecycle", "concurrency"] if a.mode == "all" else [a.mode]
    try:
        for m in modes:
            if m == "names":
                mode_names(a.seed, rng, a.slow)
            elif m == "api":
                mode_api(a.seed, rng, a.slow, a.rounds)
            elif m == "isolation":
                mode_isolation(a.seed, rng, a.slow)
            elif m == "authz":
                mode_authz(a.seed, rng, a.slow)
            elif m == "lifecycle":
                mode_lifecycle(a.seed, rng, a.slow, min(a.rounds, 60))
            elif m == "concurrency":
                mode_concurrency(a.seed, rng, a.slow, min(a.rounds, 30))
    finally:
        after = unit_restarts()
        for ip in before:
            if before[ip] != after.get(ip):
                ops.finding("F-PANIC", "unit", a.seed,
                            f"{ip} restarted during the run: {before[ip]} -> {after.get(ip)}")
                FOUND.append({"id": "F-PANIC", "tag": "unit", "seed": a.seed,
                              "msg": f"{ip} {before[ip]} -> {after.get(ip)}", "repro": "-"})
        with open(ops.os.path.join(ops.OUT, f"fuzz-{a.mode}-{a.seed}.json"), "w") as f:
            json.dump(FOUND, f, indent=1)
        log(f"=== fuzz {a.mode} done: {len(FOUND)} finding(s), "
            f"restarts-after={after} ===")
        for f_ in FOUND:
            print(f"  {f_['id']:12s} {f_['tag']}: {f_['msg'][:120]}", flush=True)


if __name__ == "__main__":
    main()

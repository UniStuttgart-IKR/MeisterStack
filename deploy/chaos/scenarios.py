#!/usr/bin/env python3
"""The named scenarios: the fault catalog of the brief (F*) and the
once-through list of things that are new and untested (S*).

Each scenario is a function that returns a list of (id, message) findings. It
sets up, acts, judges against the EXPECTED behaviour the brief names, and
tears its own objects down. Everything it creates is called chaos-*.

    ./scenarios.py --list
    ./scenarios.py S1 S2
    ./scenarios.py --all
"""

import argparse
import json
import os
import random
import re
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from invariants import (CLOUD, CLUSTER1, CLUSTER2, CLUSTERS, CLOUD_PORT, CLUSTER_PORT,
                        NODE_HOST, NODE_OF_CLUSTER, OUT, State, check, sh, items)
import mtls
import ops
from ops import (cloud, cluster, vm_body, obj, wait_for, wait_phase, wait_gone,
                 cloud_vm, cluster_vm, phase_of, log, finding, ctl, kill_agent,
                 start_agent, stop_agent, kill_controller, kill_vmm, partition)

SEED = os.environ.get("CHAOS_SEED", "-")
REG = {}


def scenario(sid, title):
    def deco(fn):
        fn.sid, fn.title = sid, title
        REG[sid] = fn
        return fn
    return deco


def mk(name, **kw):
    """Create a cloud VM, return (code, body)."""
    return cloud("POST", "/vms", vm_body(name, **kw))


def rm(name, res="vms"):
    return cloud("DELETE", f"/{res}/{name}")


def ensure_tenant(name, description="chaos scenario"):
    """A tenant to own this scenario's objects, made if it is not there.

    Since runde 4 every tenant-scoped create at the cloud needs a tenant --
    the rule a volume, a floating address and a secret always had, and which
    a VM was the exception to (D-P10). The harness runs as an admin, who is
    confined to no tenant, so it has to say which one.
    """
    c, _ = cloud("POST", "/tenants", obj("Tenant", name, {"description": description}))
    if c not in (200, 201, 409):
        log(f"tenant {name}: HTTP {c}")
    return name


def ensure_filesystem_pool(cname, name="chaos-pool"):
    """A pool this scenario can put a plain disk in, made if it needs to be.

    A create with no `pool` lands in the one marked `default`, and whether an
    estate HAS one is the estate's business: round 4's e2e ran against a lab
    whose only pool was the nvme-oF import, unmarked and with all three of its
    namespaces spoken for, so S6's every create came back
    `422 no storage pool is marked default; name one with spec.pool` and the
    scenario measured nothing at all. A scenario that only runs on estates
    shaped like the one it was written on is a scenario that reports on the
    estate instead of on the software.

    `chaos-` so that `--cleanup` knows it (`_mine`), and `filesystem` because
    that is the backend every agent in every cluster offers.
    """
    c, o = cluster(cname, "GET", "/storagepools")
    if c == 200:
        for p in (o.get("items") or []):
            if (p.get("spec") or {}).get("default"):
                return None  # the estate has one; use it, and make nothing
    c, _ = cluster(cname, "POST", "/storagepools",
                   obj("StoragePool", name, {"driver": "filesystem"}))
    if c not in (200, 201, 409):
        log(f"storage pool {name}: HTTP {c}")
        return None
    return name


def node_put(cname, node, mutate):
    """Read-modify-write one Node object on its cluster."""
    c, o = cluster(cname, "GET", f"/nodes/{node}")
    if c != 200:
        return c, o
    mutate(o)
    return cluster(cname, "PUT", f"/nodes/{node}", o)


def running_uids(node):
    rc, out = sh(node, "ps -eo args --no-headers | grep '[c]loud-hypervisor'")
    return set(re.findall(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", out))


# ============================================================================
# §4 — the once-through list
# ============================================================================

@scenario("S1", "node label + --rm, then a VM with nodeSelector")
def s1():
    f = []
    node, cname = "agent-1b", "cluster-1"
    c, _ = node_put(cname, node, lambda o: o["spec"].setdefault("labels", {}).update({"chaos-zone": "z9"}))
    if c not in (200, 201):
        return [("S1", f"labelling {node} failed: HTTP {c}")]
    c, o = cluster(cname, "GET", f"/nodes/{node}")
    if (o.get("spec", {}).get("labels") or {}).get("chaos-zone") != "z9":
        f.append(("S1", "label did not stick on the node object"))

    name = "chaos-sel-1"
    ensure_tenant("chaos-s1")
    mk(name, node_sel=None, cluster_sel=None, tenant="chaos-s1")
    rm(name)  # keep the namespace clean; the real create goes to the cluster tier
    # nodeSelector is a cluster-tier field: create straight on cluster-1.
    c, b = cluster(cname, "POST", "/vms", vm_body(name, node_sel={"chaos-zone": "z9"}))
    if c != 201:
        f.append(("S1", f"cluster create with nodeSelector: HTTP {c} {str(b)[:200]}"))
    else:
        o, secs = wait_for(lambda: (lambda x: x if (x or {}).get("spec", {}).get("nodeName") else None)(
            cluster_vm(cname, name)), 60)
        if not o:
            f.append(("S1", "VM with a satisfiable nodeSelector never got a node in 60s"))
        elif o["spec"]["nodeName"] != node:
            f.append(("S1", f"nodeSelector chaos-zone=z9 placed on {o['spec']['nodeName']}, not {node}"))
        else:
            log(f"S1 ok: placed on {node} in {secs:.0f}s")
    # unsatisfiable selector must stay pending, never land anywhere
    name2 = "chaos-sel-2"
    c, b = cluster(cname, "POST", "/vms", vm_body(name2, node_sel={"chaos-zone": "nowhere"}))
    if c == 201:
        time.sleep(20)
        o = cluster_vm(cname, name2)
        if (o or {}).get("spec", {}).get("nodeName"):
            f.append(("S1", f"unsatisfiable nodeSelector still placed on {o['spec']['nodeName']}"))
        pr = ((o or {}).get("status") or {}).get("message")
        if not pr:
            f.append(("S1", f"unsatisfiable nodeSelector: no reason, status={((o or {}).get('status'))}"))
        else:
            log(f"S1 reason={pr}")
    # --rm the label again
    node_put(cname, node, lambda o: o["spec"].get("labels", {}).pop("chaos-zone", None))
    c, o = cluster(cname, "GET", f"/nodes/{node}")
    if (o.get("spec", {}).get("labels") or {}).get("chaos-zone") is not None:
        f.append(("S1", "removing the label did not take"))
    for n in (name, name2):
        cluster(cname, "DELETE", f"/vms/{n}")
    return f


@scenario("S2", "anti-affinity, hard and soft")
def s2():
    f = []
    cname = "cluster-1"
    names = [f"chaos-aa-{i}" for i in range(1, 6)]
    anti = [{"selector": {"app": "chaos-aa"}, "required": True}]
    for n in names[:4]:
        c, b = cluster(cname, "POST", "/vms",
                       vm_body(n, mem=192, labels={"app": "chaos-aa"}, anti=anti))
        if c != 201:
            f.append(("S2", f"create {n}: HTTP {c} {str(b)[:160]}"))
    time.sleep(35)
    placed = {}
    for n in names[:4]:
        o = cluster_vm(cname, n)
        placed[n] = (o or {}).get("spec", {}).get("nodeName")
    nodes = [v for v in placed.values() if v]
    if len(nodes) != len(set(nodes)):
        f.append(("S2", f"HARD anti-affinity violated — placement {placed}"))
    log(f"S2 hard placement: {placed}")
    # cluster-1 has 4 nodes, so a 5th must stay pending on the hard term
    c, _ = cluster(cname, "POST", "/vms",
                   vm_body(names[4], mem=192, labels={"app": "chaos-aa"}, anti=anti))
    time.sleep(25)
    o = cluster_vm(cname, names[4])
    if (o or {}).get("spec", {}).get("nodeName"):
        f.append(("S2", f"5th VM with a hard anti-affinity term placed anyway on "
                        f"{o['spec']['nodeName']} — term violated"))
    else:
        log(f"S2 5th pending, reason={((o or {}).get('status') or {}).get('message')}")
    for n in names:
        cluster(cname, "DELETE", f"/vms/{n}")
    time.sleep(5)
    # soft: required=false must place even when it collides
    soft = [f"chaos-sa-{i}" for i in range(1, 7)]
    for n in soft:
        cluster(cname, "POST", "/vms",
                vm_body(n, mem=160, labels={"app": "chaos-sa"},
                        anti=[{"selector": {"app": "chaos-sa"}, "required": False}]))
    time.sleep(45)
    unplaced = [n for n in soft if not (cluster_vm(cname, n) or {}).get("spec", {}).get("nodeName")]
    if unplaced:
        f.append(("S2", f"soft anti-affinity left {unplaced} unplaced — a preference became a rule"))
    for n in soft:
        cluster(cname, "DELETE", f"/vms/{n}")
    return f


@scenario("S3", "/metrics vs the API")
def s3():
    f = []
    ports = [9100, 9090, 9000, 3002, 3003, 8080, 9256]
    found = {}
    for ip in CLOUD[:1] + CLUSTER1[:1] + ["10.128.1.106"]:
        rc, out = ctl(ip, "ss -lntp 2>/dev/null | awk '{print $4}'")
        found[ip] = out.strip()
    log(f"S3 listeners: {json.dumps(found)[:600]}")
    hits = []
    for ip in CLOUD + CLUSTER1 + ["10.128.1.106"]:
        for p in ports:
            rc, out = ctl(ip, f"timeout 3 curl -s -o /dev/null -w '%{{http_code}}' http://127.0.0.1:{p}/metrics")
            if out.strip() == "200":
                hits.append((ip, p))
    if not hits:
        f.append(("S3", "no /metrics endpoint is served anywhere in the fleet — "
                        "metrics_listen is unset in every rendered config, so I11 "
                        "(metric cardinality) cannot be observed at all"))
    else:
        log(f"S3 metrics on {hits}")
    return f


@scenario("S4", "vm logs: own guest, and a foreign tenant's VM")
def s4():
    f = []
    name = "chaos-logs-1"
    c, b = mk(name, tenant=ensure_tenant("chaos-s4"))
    if c != 201:
        return [("S4", f"create: HTTP {c} {str(b)[:200]}")]
    o, _ = wait_phase(name, "Running", 120)
    if not o:
        f.append(("S4", "VM never reached Running; log test degraded"))
    c, b = cloud("GET", f"/vms/{name}/logs")
    if c != 200:
        f.append(("S4", f"vm logs on an own, running VM: HTTP {c} {str(b)[:200]}"))
    else:
        txt = b if isinstance(b, str) else json.dumps(b)
        log(f"S4 logs {len(txt)} bytes; head={txt[:120]!r}")
        if len(txt) < 5:
            f.append(("S4", "vm logs returned an empty body for a running guest"))
    rm(name)
    return f


@scenario("S5", "tenant quota (I8)")
def s5():
    f = []
    tname = "chaos-tenant-q"
    cloud("DELETE", f"/tenants/{tname}")
    c, b = cloud("POST", "/tenants", obj("Tenant", tname,
                 {"description": "chaos quota probe",
                  "quota": {"maxVms": 2, "maxVcpus": 2, "maxMemMib": 512}}))
    if c != 201:
        return [("S5", f"tenant create: HTTP {c} {str(b)[:200]}")]
    made = []
    for i in range(1, 5):
        n = f"chaos-q-{i}"
        c, b = mk(n, vcpus=1, mem=256, tenant=tname)
        log(f"S5 create {n}: HTTP {c}")
        if c == 201:
            made.append(n)
        elif c not in (403, 409, 422):
            f.append(("S5", f"quota rejection used HTTP {c} (expected 403/409/422): {str(b)[:160]}"))
    if len(made) > 2:
        f.append(("I8", f"tenant quota maxVms=2 admitted {len(made)} VMs: {made}"))
    c, t = cloud("GET", f"/tenants/{tname}")
    log(f"S5 tenant usage after: {(t.get('status') or {})}")
    for n in made:
        rm(n)
    for n in made:
        wait_gone(n, 120)
    cloud("DELETE", f"/tenants/{tname}")
    return f


@scenario("S6", "volume outlives its VM (I9/I10) and refuses to vanish under it")
def s6():
    f = []
    cname = "cluster-1"
    vol = "chaos-vol-1"
    # D-H3: this said `sizeBytes` and `accessMode: "single"`, neither of which
    # this API has ever had -- so every create was a 422 and the fallback
    # below it retried the same wrong shape. The scenario measured nothing
    # from the day the field was named `sizeGib`, and the run still ended
    # green. A shape the server refuses is a scenario that does not run.
    spec = {"sizeGib": 1, "mode": "filesystem", "accessMode": "readWriteOnce"}
    pool = ensure_filesystem_pool(cname)
    if pool:
        spec["pool"] = pool
    c, b = cluster(cname, "POST", "/volumes", obj("Volume", vol, spec))
    if c not in (201, 200):
        return [("S6", f"volume create refused: HTTP {c} {str(b)[:250]}")]

    def volume():
        rc, o = cluster(cname, "GET", f"/volumes/{vol}")
        return o if rc == 200 else None

    o, secs = wait_for(lambda: (lambda x: x if phase_of(x) in ("Bound", "Available", "Ready")
                                else None)(volume()), 60)
    log(f"S6 volume phase after {secs:.0f}s: {phase_of(o) if o else 'n/a'}")
    name = "chaos-volvm-1"
    c, b = cluster(cname, "POST", "/vms", vm_body(
        name, volumes=[{"volume": vol}]))
    if c != 201:
        f.append(("S6", f"VM referencing a volume: HTTP {c} {str(b)[:250]}"))
    else:
        # Waited for the HOLD and not for the binding, which is what F11 is
        # about: `spec.nodeName` is written the moment the scheduler decides,
        # and the attach happens passes later. Round 4's e2e watched this
        # delete land 10 ms after the binding, with `status.attachedTo` still
        # empty -- so the volume was deleted while nobody held it, which is
        # correct, and the scenario called it "deleted out from under a VM
        # that holds it". A precondition nobody waited for is not a finding.
        def held():
            rc, o = cluster(cname, "GET", f"/volumes/{vol}")
            if rc != 200:
                return None
            return o if (o.get("status") or {}).get("attachedTo") == name else None

        holder, secs = wait_for(held, 90)
        if holder is None:
            cluster(cname, "DELETE", f"/vms/{name}")
            wait_gone(name, 120, where="cluster", cname=cname)
            cluster(cname, "DELETE", f"/volumes/{vol}")
            return f + [("S6", f"90s after its vm was bound, volume {vol} was never attached "
                               f"to it; F11 and I9 below have nothing to measure")]
        log(f"S6 volume held by {name} after {secs:.0f}s")
        # F11: delete the volume while the VM holds it
        c, b = cluster(cname, "DELETE", f"/volumes/{vol}")
        time.sleep(8)
        cc, vv = cluster(cname, "GET", f"/volumes/{vol}")
        if cc == 404:
            f.append(("F11", "volume deleted out from under a VM that holds it — "
                             "it did not stay Releasing (I9)"))
        else:
            log(f"F11 volume after delete: phase={phase_of(vv)}")
        cluster(cname, "DELETE", f"/vms/{name}")
        wait_gone(name, 120, where="cluster", cname=cname)
        # I10: the volume must outlive the VM's data
        time.sleep(10)
        cc, vv = cluster(cname, "GET", f"/volumes/{vol}")
        log(f"S6 volume after the VM went: HTTP {cc} phase={phase_of(vv) if cc==200 else '-'}")
    cluster(cname, "DELETE", f"/volumes/{vol}")
    return f


@scenario("S7", "image create with a right and a wrong checksum")
def s7():
    f = []
    for nm, spec in (
        # v1 demands metadata.name == basename(spec.source).
        ("chaos-img-ok.raw", {"format": "raw", "source": "/opt/meisterstack/images/chaos-img-ok.raw"}),
        ("chaos-img-bad.raw", {"format": "raw", "source": "/opt/meisterstack/images/chaos-img-bad.raw"}),
        ("chaos-img-url.raw", {"format": "raw", "source": "http://127.0.0.1:1/chaos-img-url.raw",
                               "checksum": "sha256:" + "0" * 64}),
    ):
        cloud("DELETE", f"/images/{nm}")
        c, b = cloud("POST", "/images", obj("Image", nm, spec))
        log(f"S7 {nm}: HTTP {c} {str(b)[:160]}")
        if nm == "chaos-img-bad.raw" and c == 201:
            time.sleep(6)
            cc, o = cloud("GET", f"/images/{nm}")
            ph = phase_of(o)
            if ph not in ("Failed",):
                f.append(("F16", f"image with a nonexistent source sits in phase {ph!r}, "
                                 f"not Failed with a message"))
        if nm == "chaos-img-url.raw" and c == 201:
            time.sleep(8)
            cc, o = cloud("GET", f"/images/{nm}")
            if phase_of(o) not in ("Failed",):
                f.append(("F16", f"image from an unreachable URL sits in phase {phase_of(o)!r}, "
                                 f"not Failed"))
        cloud("DELETE", f"/images/{nm}")
    return f


@scenario("S8", "floating pool and ip, and the double-hand-out (I14)")
def s8():
    f = []
    pool = "chaos-fpool"
    c, b = cloud("GET", "/floatingips")
    for o in items(b):
        if (o.get("spec") or {}).get("pool") == pool:
            cloud("DELETE", f"/floatingips/{o['metadata']['name']}")
    cloud("DELETE", f"/floatingpools/{pool}")
    cloud("DELETE", "/tenants/chaos-t")
    cloud("POST", "/tenants", obj("Tenant", "chaos-t", {"description": "chaos floating probe"}))
    c, b = cloud("POST", "/floatingpools", obj("FloatingPool", pool,
                 {"cidrs": ["198.51.100.0/29"], "quota": {"chaos-t": 8}}))
    log(f"S8 pool: HTTP {c} {str(b)[:160]}")
    if c != 201:
        return [("S8", f"floating pool create refused: HTTP {c} {str(b)[:250]}")]

    # An empty metadata.name is the allocator ask: take the first free gap.
    got = []
    for i in range(4):
        c, b = cloud("POST", "/floatingips",
                     {"apiVersion": "meister.io/v1", "kind": "FloatingIp",
                      "metadata": {"name": ""}, "spec": {"pool": pool, "tenant": "chaos-t"}})
        log(f"S8 allocate #{i}: HTTP {c} {str(b)[:160]}")
        if c == 201:
            got.append((b["metadata"]["name"], (b.get("spec") or {}).get("address")))
    addrs = [a for _, a in got if a]
    if len(addrs) != len(set(addrs)):
        f.append(("I14", f"the allocator handed the same address out twice: {got}"))
    for n, a in got:
        if n != a:
            f.append(("S8", f"reservation name {n!r} is not its address {a!r} — "
                            f"the name-as-CAS invariant the allocator rests on is broken"))
    # a second reservation for an address already held must be refused
    if addrs:
        c, b = cloud("POST", "/floatingips",
                     {"apiVersion": "meister.io/v1", "kind": "FloatingIp",
                      "metadata": {"name": addrs[0]},
                      "spec": {"pool": pool, "tenant": "chaos-t"}})
        log(f"S8 duplicate of {addrs[0]}: HTTP {c} {str(b)[:200]}")
        if c == 201:
            f.append(("I14", f"a second reservation for {addrs[0]} was accepted"))
    # a SECOND tenant asking for an address another tenant already holds
    cloud("DELETE", "/tenants/chaos-t2")
    cloud("POST", "/tenants", obj("Tenant", "chaos-t2", {"description": "chaos floating probe 2"}))
    c, b = cloud("PUT", f"/floatingpools/{pool}",
                 {"apiVersion": "meister.io/v1", "kind": "FloatingPool",
                  "metadata": {"name": pool},
                  "spec": {"cidrs": ["198.51.100.0/29"], "quota": {"chaos-t": 8, "chaos-t2": 4}}})
    if addrs:
        c, b = cloud("POST", "/floatingips",
                     {"apiVersion": "meister.io/v1", "kind": "FloatingIp",
                      "metadata": {"name": addrs[0]},
                      "spec": {"pool": pool, "tenant": "chaos-t2"}})
        log(f"S8 cross-tenant grab of {addrs[0]}: HTTP {c} {str(b)[:220]}")
        if c == 201:
            f.append(("I14", f"tenant chaos-t2 was given {addrs[0]}, which chaos-t already holds"))
    # exhaust the /29 and see what the refusal looks like
    for i in range(10):
        c, b = cloud("POST", "/floatingips",
                     {"apiVersion": "meister.io/v1", "kind": "FloatingIp",
                      "metadata": {"name": ""}, "spec": {"pool": pool, "tenant": "chaos-t"}})
        if c != 201:
            log(f"S8 pool exhausted at extra #{i}: HTTP {c} {str(b)[:200]}")
            break
        got.append((b["metadata"]["name"], (b.get("spec") or {}).get("address")))
    else:
        f.append(("I14", f"a /29 pool handed out more than 14 addresses: {[a for _,a in got]}"))
    seen = [a for _, a in got]
    if len(seen) != len(set(seen)):
        f.append(("I14", f"duplicate addresses across the whole run: {seen}"))
    log(f"S8 total handed out: {seen}")
    for n, _ in got:
        cloud("DELETE", f"/floatingips/{n}")
    cloud("DELETE", f"/floatingpools/{pool}")
    for t in ("chaos-t", "chaos-t2"):
        cloud("DELETE", f"/tenants/{t}")
    return f


@scenario("S9", "spread vs first-fit stacking")
def s9():
    f = []
    cname = "cluster-1"
    names = [f"chaos-sp-{i}" for i in range(1, 5)]
    for n in names:
        cluster(cname, "POST", "/vms", vm_body(n, mem=160))
    time.sleep(40)
    where = {n: (cluster_vm(cname, n) or {}).get("spec", {}).get("nodeName") for n in names}
    log(f"S9 placement (config says first-fit unless changed): {where}")
    for n in names:
        cluster(cname, "DELETE", f"/vms/{n}")
    return f


@scenario("S10", "tenant isolation and the VNI lifecycle")
def s10():
    f = []
    ta, tb = "chaos-ta", "chaos-tb"
    for t in (ta, tb):
        cloud("DELETE", f"/tenants/{t}")
    vnis = {}
    for t in (ta, tb):
        c, b = cloud("POST", "/tenants", obj("Tenant", t, {"description": "chaos isolation probe"}))
        if c != 201:
            return [("S10", f"tenant {t}: HTTP {c} {str(b)[:200]}")]
        vnis[t] = (b.get("spec") or {}).get("vni")
    log(f"S10 vnis: {vnis}")
    if vnis[ta] == vnis[tb]:
        f.append(("S10", f"two tenants got the same VNI {vnis[ta]} — one broadcast domain"))
    names = {}
    for t in (ta, tb):
        n = f"chaos-net-{t}"
        names[t] = n
        c, b = mk(n, tenant=t, nics=[{"bridge": None}] if False else [{}])
        log(f"S10 create {n}: HTTP {c} {str(b)[:200]}")
        if c != 201:
            c, b = mk(n, tenant=t)
            log(f"S10 create {n} (no nic): HTTP {c}")
    for t in (ta, tb):
        o, secs = wait_phase(names[t], "Running", 150)
        if not o:
            oo = cloud_vm(names[t])
            f.append(("S10", f"tenant VM {names[t]} never ran: phase="
                             f"{phase_of(oo)!r} msg={((oo or {}).get('status') or {}).get('message')!r}"))
    # which VNIs exist on the nodes now
    for node in NODE_OF_CLUSTER["cluster-1"] + NODE_OF_CLUSTER["cluster-2"]:
        rc, out = sh(node, "ip -d link show type vxlan 2>/dev/null | grep -oE 'vxlan id [0-9]+' | awk '{print $3}' | tr '\\n' ' '")
        log(f"S10 vnis on {node}: {out.strip()}")
    before = {}
    for node in NODE_OF_CLUSTER["cluster-1"]:
        rc, out = sh(node, "nft list ruleset 2>/dev/null | wc -l")
        before[node] = out.strip()
    log(f"S10 nft lines per node: {before}")
    for t in (ta, tb):
        rm(names[t])
    for t in (ta, tb):
        wait_gone(names[t], 150)
    for t in (ta, tb):
        cloud("DELETE", f"/tenants/{t}")
    time.sleep(15)
    leaked = {}
    for node in NODE_OF_CLUSTER["cluster-1"] + NODE_OF_CLUSTER["cluster-2"]:
        rc, out = sh(node, "ip -d link show type vxlan 2>/dev/null | grep -oE 'vxlan id [0-9]+' | awk '{print $3}' | tr '\\n' ' '")
        here = set(out.split())
        gone = here & {str(v) for v in vnis.values() if v}
        if gone:
            leaked[node] = sorted(gone)
    if leaked:
        f.append(("I3", f"VXLAN devices for deleted tenants' VNIs survive on {leaked} — "
                        f"a delete left a wire behind"))
    return f


@scenario("S11", "a node cordoned while creates run (F13)")
def s11():
    f = []
    cname = "cluster-1"
    nodes = NODE_OF_CLUSTER[cname]
    live_before = {n: running_uids(n) for n in nodes}
    for n in nodes:
        node_put(cname, n, lambda o: o["spec"].update({"schedulable": False}))
    time.sleep(2)
    name = "chaos-cordon-1"
    c, b = cluster(cname, "POST", "/vms", vm_body(name, mem=160))
    time.sleep(25)
    o = cluster_vm(cname, name)
    placed = (o or {}).get("spec", {}).get("nodeName")
    reason = ((o or {}).get("status") or {}).get("message")
    if placed:
        f.append(("F13", f"a VM was placed on {placed} while EVERY node was cordoned"))
    elif not reason:
        f.append(("F13", f"cordoned-everywhere VM has no reason; status={((o or {}).get('status'))}"))
    else:
        log(f"F13 reason={reason}")
    live_after = {n: running_uids(n) for n in nodes}
    for n in nodes:
        if live_before[n] - live_after[n]:
            f.append(("F13", f"cordoning {n} disturbed running VMs: lost {live_before[n]-live_after[n]}"))
    for n in nodes:
        node_put(cname, n, lambda o: o["spec"].update({"schedulable": True}))
    o, secs = wait_for(lambda: (lambda x: x if (x or {}).get("spec", {}).get("nodeName") else None)(
        cluster_vm(cname, name)), 90)
    if not o:
        f.append(("F13", "after uncordoning every node the pending VM was still not placed after 90s"))
    else:
        log(f"F13 placed {secs:.0f}s after uncordon on {o['spec']['nodeName']}")
    cluster(cname, "DELETE", f"/vms/{name}")
    return f


@scenario("S12", "overbooking a node (F12/I5)")
def s12():
    f = []
    cname = "cluster-2"          # 2 small nodes, ~1.9 GiB each — cheapest to fill
    nodes = NODE_OF_CLUSTER[cname]
    caps = {}
    c, b = cluster(cname, "GET", "/nodes")
    for n in items(b):
        caps[n["metadata"]["name"]] = (n.get("status", {}).get("capacity") or {}).get("memMib", 0)
    total = sum(caps.values())
    log(f"S12 cluster-2 capacity: {caps} total {total} MiB")
    made = []
    per = 512
    want = int(total / per) + 4
    for i in range(want):
        n = f"chaos-fill-{i}"
        c, b = cluster(cname, "POST", "/vms", vm_body(n, mem=per))
        if c == 201:
            made.append(n)
        else:
            log(f"S12 create {n} refused: HTTP {c} {str(b)[:140]}")
    time.sleep(50)
    booked = {}
    pend = []
    for n in made:
        o = cluster_vm(cname, n) or {}
        nd = o.get("spec", {}).get("nodeName")
        if nd:
            booked[nd] = booked.get(nd, 0) + per
        else:
            pend.append(((o.get("status") or {}).get("message"), n))
    log(f"S12 booked per node: {booked}; pending {len(pend)} reasons={sorted({p for p,_ in pend})}")
    for nd, mem in booked.items():
        if caps.get(nd) and mem > caps[nd]:
            f.append(("I5", f"{cname}/{nd}: {mem} MiB bound over a {caps[nd]} MiB node"))
    if pend and not any(p for p, _ in pend):
        f.append(("F12", "VMs that did not fit are pending with NO reason set"))
    # and did the ones that were placed actually start?
    ran = sum(1 for n in made if phase_of(cluster_vm(cname, n)) == "Running")
    log(f"S12 running {ran}/{len(made)}")
    for n in made:
        cluster(cname, "DELETE", f"/vms/{n}")
    for n in made:
        wait_gone(n, 120, where="cluster", cname=cname)
    return f


@scenario("S13", "OIDC is in main: IdP unreachable (F17) and a deleted User (F18)")
def s13():
    f = []
    c, b = cloud("GET", "/users")
    if c != 200:
        return [("S13", f"users endpoint: HTTP {c}")]
    log(f"S13 users: {[u['metadata']['name'] for u in items(b)]}")

    # D-H1: this line used to be a CONSTANT. It said "the cloud REST edge
    # answers unauthenticated plaintext HTTP", appended unconditionally,
    # without ever looking at the code it interpolated -- and it was still
    # being written in rollout 59, five images after mTLS was turned on. A
    # security statement that survives the change disproving it is worse
    # than no statement: somebody reads it and believes the edge is open.
    #
    # So it is measured, in three questions, and only an answer that
    # contradicts the design becomes a finding.
    path = "/apis/meister.io/v1/vms"
    if not mtls.available():
        # A lab that was deliberately started with auth off. That is a
        # configuration and not a defect, and the harness cannot tell the
        # difference from here -- it says what it is looking at and stops.
        log(f"S13 transport: {mtls.describe()}; the edge's auth is not measurable from here")
        return f
    plain = mtls.probe(CLOUD[0], CLOUD_PORT, path, scheme_="http")
    naked = mtls.probe(CLOUD[0], CLOUD_PORT, path, client_cert=False)
    full = mtls.probe(CLOUD[0], CLOUD_PORT, path, client_cert=True)
    log(f"S13 edge: http -> {plain}, https without a client cert -> {naked}, with one -> {full}")

    if plain != 0:
        f.append(("SEC", f"the cloud REST edge answers plaintext http: GET {path} -> {plain}. "
                         "Every token and every object on that port travels in the clear"))
    if naked == 200:
        f.append(("SEC", f"the cloud REST edge served GET {path} to a caller with no client "
                         "certificate and no bearer; it lists every tenant's VMs"))
    elif naked not in (401, 403, 0):
        f.append(("SEC", f"an unauthenticated https request answered {naked}; expected 401"))
    if full != 200:
        # Not a finding about the fleet: it is the harness saying its own
        # credential no longer works, which invalidates every other number
        # in this run.
        f.append(("S13", f"the break-glass identity was answered {full} at the cloud edge; "
                         f"the rest of this run was measured with a credential that is not "
                         f"getting through ({mtls.describe()})"))
    return f


@scenario("S14", "storage node without a hypervisor")
def s14():
    f = []
    node = "agent-2b"
    rc, out = sh(node, "cat /run/meisterstack/agent.toml")
    if "[hypervisor" not in out:
        return [("S14", "agent-2b already has no hypervisor section — nothing to prove")]
    # awk and not python3: **the lab image has no python3** (`command -v
    # python3` on agent-2b: nothing), so the edit below was a no-op, the agent
    # restarted with its hypervisor section intact, and the scenario reported
    # a node that "still advertises hypervisor/cloud-hypervisor" 60s later. It
    # did, correctly, about a config nobody had changed. Third false finding
    # this scenario has produced, and the first two were about reading a race
    # once (D-H5) — this one is about not checking that the setup happened.
    sh(node, "cp /run/meisterstack/agent.toml /run/meisterstack/agent.toml.chaos-bak && "
             "awk '/^\\[hypervisor/{skip=1} /^\\[/&&!/^\\[hypervisor/{skip=0} !skip' "
             "/run/meisterstack/agent.toml.chaos-bak > /run/meisterstack/agent.toml")
    # ...and the check that makes the rest of this scenario mean anything. A
    # setup that did not happen must end the scenario, never feed it.
    rc, after = sh(node, "cat /run/meisterstack/agent.toml")
    if "[hypervisor" in after:
        sh(node, "cp /run/meisterstack/agent.toml.chaos-bak /run/meisterstack/agent.toml; "
                 "rm -f /run/meisterstack/agent.toml.chaos-bak")
        return [("S14", "the setup did not take: [hypervisor] is still in agent.toml on "
                        f"{node}, so nothing below would have measured the agent")]
    sh(node, "systemctl restart meister-agent")
    time.sleep(20)
    rc, out = sh(node, "systemctl is-active meister-agent")
    log(f"S14 agent without [hypervisor]: {out.strip()}")
    if out.strip() != "active":
        rc2, j = sh(node, "journalctl -u meister-agent --no-pager -n 12 | tail -8")
        f.append(("S14", f"an agent with no [hypervisor] section does not start: {j.strip()[:300]}"))
    else:
        # D-H5: this read the node object ONCE, twenty seconds after the
        # restart, and called what it found a defect. The capabilities come
        # off the agent's Hello, and until that Hello has landed the object
        # still carries the answer from before the restart -- so the finding
        # was about a stale read, was withdrawn as one, and was produced
        # again in rollout 59. A race read once is not a measurement.
        #
        # Waited for instead: the list has up to 60s to lose the hypervisor
        # entries, and only a list that still has them then is a finding.
        def caps_now():
            rc, o = cluster("cluster-2", "GET", f"/nodes/{node}")
            if rc != 200:
                return None
            return ((o.get("status") or {}).get("capacity") or {}).get("capabilities", [])

        # `True` and not the list itself: an empty list is falsy, and
        # `wait_for` polls until something is truthy.
        gone, secs = wait_for(
            lambda: (lambda caps: True if caps is not None
                     and not any(x.startswith("hypervisor/") for x in caps) else None)(caps_now()),
            60)
        caps = caps_now()
        if gone is None:
            f.append(("S14", f"60s after a restart with no [hypervisor] section, {node} still "
                             f"advertises {[x for x in (caps or []) if x.startswith('hypervisor/')]}"))
        else:
            log(f"S14 hypervisor capabilities gone after {secs:.0f}s; now {caps}")
    sh(node, "mv -f /run/meisterstack/agent.toml.chaos-bak /run/meisterstack/agent.toml && "
             "systemctl restart meister-agent")
    time.sleep(15)
    return f


# ============================================================================
# §3 — the fault catalog
# ============================================================================

@scenario("F1", "agent SIGKILL: VMs run on, node NotReady, restart adopts")
def f1():
    f = []
    node, cname = "agent-1a", "cluster-1"
    name = "chaos-f1"
    cluster(cname, "POST", "/vms", vm_body(name, mem=192))
    o, _ = wait_for(lambda: (lambda x: x if phase_of(x) == "Running" else None)(
        cluster_vm(cname, name)), 120)
    if not o:
        return [("F1", "setup: the probe VM never ran")]
    node = o["spec"]["nodeName"]
    before = running_uids(node)
    kill_agent(node)
    time.sleep(4)
    mid = running_uids(node)
    if before - mid:
        f.append(("F1", f"killing the agent on {node} took its VMs down: lost {before-mid}"))

    # D-H4: this used to wait 90s for the node to go NotReady and report a
    # finding when it did not -- and it never did, because the unit carries
    # `Restart=always`. systemd puts the agent back in seconds, it dials in
    # again, and the heartbeat never expires. The line was withdrawn as an
    # artefact on 2026-08-29 and the scenario went on producing it in
    # rollout 59: a SUPERVISED agent coming straight back is the system
    # working, and a harness that calls it a defect trains people to skip
    # its output.
    #
    # So what is measured is what actually has to be true: the agent comes
    # back on its own. A node that DOES go NotReady in the window is worth a
    # line -- it means the restart took longer than the heartbeat -- and it
    # is not a finding either.
    back, secs = wait_for(lambda: (lambda rc_out: True if rc_out[1].strip() == "active" else None)(
        sh(node, "systemctl is-active meister-agent")), 90)
    if not back:
        f.append(("F1", f"the agent on {node} did not come back 90s after SIGKILL; the unit "
                        f"carries Restart=always and nothing restarted it"))
    else:
        ready = (cluster(cname, "GET", f"/nodes/{node}")[1].get("status") or {}).get("ready")
        log(f"F1 agent back after {secs:.0f}s; the node read ready={ready} at that moment")
    start_agent(node)
    back, secs = wait_for(lambda: (lambda x: True if (x.get("status") or {}).get("ready") else None)(
        cluster(cname, "GET", f"/nodes/{node}")[1]), 120)
    log(f"F1 ready again after {secs:.0f}s")
    time.sleep(20)
    after = running_uids(node)
    if before - after:
        f.append(("F1", f"the restarted agent did not adopt: {before-after} no longer running"))
    o = cluster_vm(cname, name)
    if phase_of(o) not in ("Running",):
        f.append(("F1", f"after agent restart the adopted VM reads {phase_of(o)!r}, not Running"))
    cluster(cname, "DELETE", f"/vms/{name}")
    return f


@scenario("F2", "agent stopped for real: node NotReady, VMs survive, restart adopts")
def f2():
    f = []
    cname = "cluster-1"
    name = "chaos-f2"
    cluster(cname, "DELETE", f"/vms/{name}")
    wait_gone(name, 90, where="cluster", cname=cname)
    cluster(cname, "POST", "/vms", vm_body(name, mem=192))
    o, _ = wait_for(lambda: (lambda x: x if phase_of(x) == "Running" else None)(
        cluster_vm(cname, name)), 120)
    if not o:
        return [("F2", "setup: the probe VM never ran")]
    node = o["spec"]["nodeName"]
    before = running_uids(node)
    stop_agent(node)          # the restart policy does not undo a stop
    t0 = time.time()
    nr, secs = wait_for(lambda: (lambda x: True if x and not (x.get("status") or {}).get("ready") else None)(
        cluster(cname, "GET", f"/nodes/{node}")[1]), 90)
    if not nr:
        f.append(("F2", f"{node} was still Ready 90 s after its agent was stopped — "
                        f"the heartbeat watchdog did not fire"))
    else:
        log(f"F2 NotReady after {secs:.0f}s (watchdog budget 30 s)")
    mid = running_uids(node)
    if before - mid:
        f.append(("F2", f"stopping the agent on {node} took its VMs down: lost {before - mid}"))
    o = cluster_vm(cname, name)
    log(f"F2 vm while the node is NotReady: phase={phase_of(o)!r} "
        f"msg={((o or {}).get('status') or {}).get('message')!r}")
    start_agent(node)
    back, secs = wait_for(lambda: (lambda x: True if (x.get("status") or {}).get("ready") else None)(
        cluster(cname, "GET", f"/nodes/{node}")[1]), 120)
    if not back:
        f.append(("F2", f"{node} never came back Ready 120 s after its agent was started"))
    else:
        log(f"F2 Ready again after {secs:.0f}s")
    time.sleep(25)
    after = running_uids(node)
    if before - after:
        f.append(("F2", f"the restarted agent did not adopt: {before - after} no longer running"))
    o = cluster_vm(cname, name)
    if phase_of(o) != "Running":
        f.append(("F2", f"after adoption the VM reads {phase_of(o)!r}, not Running"))
    cluster(cname, "DELETE", f"/vms/{name}")
    return f


@scenario("F7", "agent <-> cluster partition (DROP): dial gives up after 3.0 s")
def f7():
    f = []
    cname = "cluster-1"
    node = "agent-1b"
    name = "chaos-f7"
    cluster(cname, "DELETE", f"/vms/{name}")
    wait_gone(name, 90, where="cluster", cname=cname)
    c, o = cluster(cname, "GET", f"/nodes/{node}")
    before_ready = (o.get("status") or {}).get("ready")
    live_before = running_uids(node)
    partition(node, CLUSTER1, on=True)
    log(f"F7 {node} blackholed from {CLUSTER1}")
    try:
        nr, secs = wait_for(lambda: (lambda x: True if x and not (x.get("status") or {}).get("ready") else None)(
            cluster(cname, "GET", f"/nodes/{node}")[1]), 120)
        if not nr:
            f.append(("F7", f"{node} stayed Ready 120 s into a DROP partition"))
        else:
            log(f"F7 NotReady after {secs:.0f}s")
        live_mid = running_uids(node)
        if live_before - live_mid:
            f.append(("F7", f"a partition took VMs down on {node}: {live_before - live_mid}"))
        # how long does one dial attempt actually take against a blackhole?
        rc, out = sh(node, "journalctl -u meister-agent --since '-3 min' --no-pager 2>/dev/null | "
                           "grep -icE 'session failed|transport error|deadline|timeout'")
        log(f"F7 dial-failure lines in the agent journal: {out.strip()}")
        rc, out = sh(node, "S=$(date +%s%N); timeout 30 bash -c "
                           "'exec 3<>/dev/tcp/10.128.1.104/50051' 2>/dev/null; "
                           "E=$(date +%s%N); echo $(( (E-S)/1000000 ))", timeout=45)
        ms = out.strip()
        log(f"F7 a raw TCP connect into the blackhole took {ms} ms "
            f"(proto::DIAL_TIMEOUT is 3000 ms)")
    finally:
        partition(node, CLUSTER1, on=False)
        log(f"F7 partition lifted on {node}")
    back, secs = wait_for(lambda: (lambda x: True if (x.get("status") or {}).get("ready") else None)(
        cluster(cname, "GET", f"/nodes/{node}")[1]), 150)
    if not back:
        f.append(("F7", f"{node} did not come back Ready 150 s after the partition was lifted"))
    else:
        log(f"F7 Ready again {secs:.0f}s after the partition lifted")
    time.sleep(20)
    live_after = running_uids(node)
    if live_before - live_after:
        f.append(("F7", f"after the partition healed, {node} is missing {live_before - live_after}"))
    # no VM may be bound twice across the partition
    dupes = {}
    for cn in CLUSTERS:
        for v in items(cluster(cn, "GET", "/vms")[1]):
            nd = v["spec"].get("nodeName")
            if nd:
                dupes.setdefault(v["metadata"]["uid"], set()).add((cn, nd))
    for u, places in dupes.items():
        if len(places) > 1:
            f.append(("F7", f"after the partition healed, uid {u} is bound to {sorted(places)}"))
    return f


@scenario("F3", "one cluster replica SIGKILL — only its agents move (I15)")
def f3():
    f = []
    cname = "cluster-1"
    def homes():
        h = {}
        for node in NODE_OF_CLUSTER[cname]:
            rc, out = sh(node, "journalctl -u meister-agent --no-pager -n 200 2>/dev/null | "
                               "grep -oE 'http://10\\.128\\.1\\.[0-9]+:50051' | tail -1")
            h[node] = out.strip()
        return h
    before = homes()
    log(f"F3 homes before: {before}")
    victim = CLUSTER1[0]
    kill_controller(victim, "meister-cluster-controller")
    time.sleep(25)
    after = homes()
    log(f"F3 homes after:  {after}")
    moved = {n for n in before if before[n] != after[n] and before[n]}
    should = {n for n in before if victim in before[n]}
    if moved - should:
        f.append(("I15", f"killing {victim} moved agents that were not homed on it: {moved-should}"))
    time.sleep(20)
    rc, out = ctl(victim, "systemctl is-active meister-cluster-controller")
    if out.strip() != "active":
        ctl(victim, "systemctl start meister-cluster-controller")
    return f


@scenario("F4", "all cluster replicas down: agents autonomous, no VM dies")
def f4():
    f = []
    cname = "cluster-1"
    name = "chaos-f4"
    cluster(cname, "POST", "/vms", vm_body(name, mem=192))
    o, _ = wait_for(lambda: (lambda x: x if phase_of(x) == "Running" else None)(
        cluster_vm(cname, name)), 120)
    if not o:
        return [("F4", "setup: probe VM never ran")]
    node = o["spec"]["nodeName"]
    before = {n: running_uids(n) for n in NODE_OF_CLUSTER[cname]}
    for ip in CLUSTER1:
        ctl(ip, "systemctl stop meister-cluster-controller")
    log("F4 all cluster-1 replicas stopped")
    time.sleep(90)
    restore = lambda: [ctl(ip, "systemctl start meister-cluster-controller") for ip in CLUSTER1]
    after = {n: running_uids(n) for n in NODE_OF_CLUSTER[cname]}
    for n in before:
        if before[n] - after[n]:
            f.append(("F4", f"with no controller alive, {n} lost VMs {before[n]-after[n]}"))
    # a create must simply not happen — and must not be lost either
    try:
        c, b = ops.call(CLUSTER1[0], CLUSTER_PORT, "POST", "/apis/meister.io/v1/vms",
                        vm_body("chaos-f4-b", mem=160))
        log(f"F4 create against a dead API: HTTP {c}")
        if c == 201:
            f.append(("F4", "a create was accepted while every replica of the tier was stopped"))
    except ops.ApiError as e:
        log(f"F4 create against a dead API: refused at the transport ({e})")
    restore()
    time.sleep(30)
    healed = {n: running_uids(n) for n in NODE_OF_CLUSTER[cname]}
    for n in before:
        if before[n] - healed[n]:
            f.append(("F4", f"after the controllers came back, {n} is missing {before[n]-healed[n]}"))
    cluster(cname, "DELETE", f"/vms/{name}")
    cluster(cname, "DELETE", "/vms/chaos-f4-b")
    return f


@scenario("F5", "cloud controller gone: both clusters keep running")
def f5():
    f = []
    before = {}
    for cn in CLUSTERS:
        before[cn] = {n: running_uids(n) for n in NODE_OF_CLUSTER[cn]}
    for ip in CLOUD:
        ctl(ip, "systemctl stop meister-cloud-controller")
    time.sleep(60)
    for cn in CLUSTERS:
        c, b = cluster(cn, "GET", "/vms")
        if c != 200:
            f.append(("F5", f"{cn} REST stopped answering while the cloud tier was down: HTTP {c}"))
        after = {n: running_uids(n) for n in NODE_OF_CLUSTER[cn]}
        for n in before[cn]:
            if before[cn][n] - after[n]:
                f.append(("F5", f"cloud down took VMs off {n}: {before[cn][n]-after[n]}"))
    # a cluster-local create must still work
    c, b = cluster("cluster-1", "POST", "/vms", vm_body("chaos-f5", mem=160))
    o, secs = wait_for(lambda: (lambda x: x if phase_of(x) == "Running" else None)(
        cluster_vm("cluster-1", "chaos-f5")), 120)
    if not o:
        f.append(("F5", "with the cloud tier down, a cluster-local create never reached Running"))
    else:
        log(f"F5 cluster-local create ran in {secs:.0f}s with no cloud")
    for ip in CLOUD:
        ctl(ip, "systemctl start meister-cloud-controller")
    time.sleep(25)
    cluster("cluster-1", "DELETE", "/vms/chaos-f5")
    return f


@scenario("F8", "kill the VMM process: quarantine, then restart")
def f8():
    f = []
    cname = "cluster-1"
    name = "chaos-f8"
    cluster(cname, "POST", "/vms", vm_body(name, mem=192))
    o, _ = wait_for(lambda: (lambda x: x if phase_of(x) == "Running" else None)(
        cluster_vm(cname, name)), 120)
    if not o:
        return [("F8", "setup: probe VM never ran")]
    node, u = o["spec"]["nodeName"], o["metadata"]["uid"]
    kill_vmm(node, u)
    seen = []
    t0 = time.time()
    while time.time() - t0 < 150:
        p = phase_of(cluster_vm(cname, name))
        if p and (not seen or seen[-1] != p):
            seen.append(p)
        if p == "Running" and len(seen) > 1:
            break
        time.sleep(3)
    log(f"F8 phases after the vmm was killed: {seen} in {time.time()-t0:.0f}s")
    if "Running" not in seen[1:]:
        f.append(("F8", f"a killed vmm never came back: phases {seen}"))
    cluster(cname, "DELETE", f"/vms/{name}")
    return f


@scenario("F9", "two replicas schedule at once — CAS lets one win")
def f9():
    f = []
    cname = "cluster-1"
    names = [f"chaos-f9-{i}" for i in range(8)]
    import concurrent.futures as cf
    with cf.ThreadPoolExecutor(max_workers=8) as ex:
        list(ex.map(lambda t: ops.call(CLUSTER1[t[0] % len(CLUSTER1)], CLUSTER_PORT, "POST",
                                       "/apis/meister.io/v1/vms", vm_body(t[1], mem=160)),
                    list(enumerate(names))))
    time.sleep(45)
    for n in names:
        o = cluster_vm(cname, n)
        nd = (o or {}).get("spec", {}).get("nodeName")
        if not nd:
            continue
        on = [x for x in NODE_OF_CLUSTER[cname] if (o["metadata"]["uid"] in "".join(
            sh(x, "ps -eo args --no-headers | grep '[c]loud-hypervisor'")[1]))]
        if len(on) > 1:
            f.append(("F9", f"{n} runs on {on} — two schedulers both won"))
    for n in names:
        cluster(cname, "DELETE", f"/vms/{n}")
    for n in names:
        wait_gone(n, 120, where="cluster", cname=cname)
    return f


@scenario("F10", "kill the controller between provision and the write-back")
def f10():
    f = []
    cname = "cluster-1"
    name = "chaos-f10"
    for attempt in range(3):
        cluster(cname, "DELETE", f"/vms/{name}")
        wait_gone(name, 90, where="cluster", cname=cname)
        c, b = cluster(cname, "POST", "/vms", vm_body(name, mem=192))
        if c != 201:
            return [("F10", f"create: HTTP {c}")]
        time.sleep(1.2 + attempt * 0.8)
        for ip in CLUSTER1:
            kill_controller(ip, "meister-cluster-controller")
        time.sleep(20)
        for ip in CLUSTER1:
            ctl(ip, "systemctl start meister-cluster-controller")
        o, secs = wait_for(lambda: (lambda x: x if phase_of(x) == "Running" else None)(
            cluster_vm(cname, name)), 180)
        if not o:
            oo = cluster_vm(cname, name)
            f.append(("F10", f"attempt {attempt}: VM never recovered after a mid-provision kill; "
                             f"phase={phase_of(oo)!r} msg={((oo or {}).get('status') or {}).get('message')!r}"))
            break
        node = o["spec"]["nodeName"]
        rc, out = sh(node, f"ls -la /var/lib/meisterstack/volumes 2>/dev/null | grep -c . ; "
                           f"ls /var/lib/meisterstack/volumes 2>/dev/null | grep -c '{o['metadata']['uid']}'")
        nums = [int(x) for x in out.split() if x.isdigit()]
        if len(nums) > 1 and nums[1] > 1:
            f.append(("F10", f"attempt {attempt}: {nums[1]} backing files exist for one VM uid "
                             f"on {node} — provision ran twice"))
        log(f"F10 attempt {attempt}: recovered in {secs:.0f}s on {node}, backing files={nums}")
    cluster(cname, "DELETE", f"/vms/{name}")
    return f


@scenario("F15", "a guest that floods the console")
def f15():
    f = []
    cname = "cluster-1"
    name = "chaos-f15"
    c, b = cluster(cname, "POST", "/vms", vm_body(
        name, mem=192,
        volumes=[{"base_image": "tiny-volume.raw", "size_bytes": 67108864}]))
    o, _ = wait_for(lambda: (lambda x: x if phase_of(x) == "Running" else None)(
        cluster_vm(cname, name)), 120)
    if not o:
        cluster(cname, "DELETE", f"/vms/{name}")
        return [("F15", "setup: probe VM never ran")]
    node = o["spec"]["nodeName"]
    rc, d0 = sh(node, "df -k --output=avail / | tail -1; du -sk /run/meisterstack 2>/dev/null | cut -f1")
    time.sleep(60)
    rc, d1 = sh(node, "df -k --output=avail / | tail -1; du -sk /run/meisterstack 2>/dev/null | cut -f1")
    log(f"F15 disk before/after 60s: {d0.split()} / {d1.split()}")
    c, b = cluster(cname, "GET", f"/vms/{name}/logs")
    txt = b if isinstance(b, str) else json.dumps(b)
    log(f"F15 log body {len(txt)} bytes")
    if len(txt) > 4 * 1024 * 1024:
        f.append(("F15", f"vm logs handed back {len(txt)} bytes in one response — no ring bound"))
    cluster(cname, "DELETE", f"/vms/{name}")
    return f


@scenario("I12", "no event per reconcile pass — ten quiet minutes")
def i12():
    f = []
    out = {}
    for cn in CLUSTERS:
        c, b = cluster(cn, "GET", "/events")
        out[cn] = len(items(b))
    log(f"I12 events before: {out}")
    time.sleep(600)
    grew = {}
    for cn in CLUSTERS:
        c, b = cluster(cn, "GET", "/events")
        grew[cn] = len(items(b))
    log(f"I12 events after 10 quiet minutes: {grew}")
    for cn in CLUSTERS:
        if grew[cn] > out[cn]:
            c, b = cluster(cn, "GET", "/events")
            latest = sorted(items(b), key=lambda e: e["metadata"]["creationTimestamp"])[-3:]
            f.append(("I12", f"{cn} grew {grew[cn]-out[cn]} events in ten idle minutes: "
                             f"{[ (e['metadata']['name'], e['spec'].get('reason')) for e in latest ]}"))
    return f


@scenario("I13", "nothing grows monotonically — redb, fds, rss")
def i13():
    f = []
    def sample():
        s = {}
        for node in NODE_HOST:
            rc, out = sh(node, "stat -c %s /var/lib/meisterstack/agent.redb 2>/dev/null || echo 0; "
                               "P=$(systemctl show -p MainPID --value meister-agent); "
                               "[ \"$P\" != 0 ] && (ls /proc/$P/fd 2>/dev/null|wc -l; "
                               "grep VmRSS /proc/$P/status|awk '{print $2}') || echo '0 0'")
            nums = [int(x) for x in out.split() if x.isdigit()]
            s[node] = nums[:3]
        for ip in CLOUD[:1] + CLUSTER1[:1]:
            unit = "meister-cloud-controller" if ip in CLOUD else "meister-cluster-controller"
            rc, out = ctl(ip, f"P=$(systemctl show -p MainPID --value {unit}); "
                              f"ls /proc/$P/fd 2>/dev/null|wc -l; grep VmRSS /proc/$P/status|awk '{{print $2}}'")
            s[ip] = [int(x) for x in out.split() if x.isdigit()][:2]
        return s
    a = sample()
    log(f"I13 t0: {json.dumps(a)}")
    time.sleep(900)
    b = sample()
    log(f"I13 t+15min: {json.dumps(b)}")
    for k in a:
        for i, (x, y) in enumerate(zip(a[k], b[k])):
            if x and y > x * 1.5 and y - x > 2000:
                f.append(("I13", f"{k} metric#{i} grew {x} -> {y} in 15 idle minutes"))
    with open(os.path.join(OUT, "growth.json"), "a") as fh:
        fh.write(json.dumps({"t0": a, "t1": b}) + "\n")
    return f


@scenario("I6", "the anti-affinity reproducer: bursts of creates one pass sees together")
def i6():
    """The headline finding of the run, in a form somebody else can re-run.

    A required anti-affinity term is only measured against `Candidate.hosted`,
    which is derived once per reconcile pass. place() spends the capacity of a
    binding under the pass lock (controller_api::deduct) and never adds the
    bound VM's labels to that list, so every further VM of the same pass is
    judged against an inventory from before the pass started. Three rounds,
    because a burst that happens to be split over two passes places correctly
    and would read as a pass.
    """
    f = []
    cn = "cluster-1"
    anti = [{"selector": {"grp": "i6"}, "required": True}]
    import concurrent.futures as cf
    for rnd in range(3):
        names = [f"chaos-i6-{rnd}-{i}" for i in range(6)]
        with cf.ThreadPoolExecutor(max_workers=6) as ex:
            list(ex.map(lambda n: cluster(cn, "POST", "/vms",
                        vm_body(n, mem=160, labels={"grp": "i6"}, anti=anti)), names))
        time.sleep(30)
        place = {}
        for n in names:
            nd = (cluster_vm(cn, n) or {}).get("spec", {}).get("nodeName")
            if nd:
                place.setdefault(nd, []).append(n)
        log(f"I6 round {rnd}: {place}")
        stacked = {k: v for k, v in place.items() if len(v) > 1}
        if stacked:
            f.append(("I6", f"round {rnd}: a required anti-affinity term put {stacked} "
                            f"on one node while other nodes were free"))
        for n in names:
            cluster(cn, "DELETE", f"/vms/{n}")
        for n in names:
            wait_gone(n, 150, where="cluster", cname=cn)
    return f


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ids", nargs="*")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--all", action="store_true")
    a = ap.parse_args()
    if a.list:
        for k in sorted(REG):
            print(f"{k:5} {REG[k].title}")
        return 0
    ids = sorted(REG) if a.all else a.ids
    total = 0
    for sid in ids:
        fn = REG.get(sid)
        if not fn:
            print(f"unknown scenario {sid}")
            continue
        log(f"=== {sid}: {fn.title}")
        t0 = time.time()
        try:
            found = fn() or []
        except Exception as e:
            found = [(sid, f"the scenario itself blew up: {type(e).__name__}: {e}")]
        for fid, msg in found:
            finding(fid, sid, SEED, msg)
        total += len(found)
        # every scenario is followed by a full invariant sweep
        st = State()
        base = json.load(open(os.path.join(OUT, "baseline.json"))) if os.path.exists(
            os.path.join(OUT, "baseline.json")) else {}
        for fid, msg in check(st, base):
            finding(fid, f"{sid}-after", SEED, msg)
            total += 1
        log(f"=== {sid} done in {time.time()-t0:.0f}s")
    print(f"\n{total} finding line(s); see {OUT}/findings.txt")
    return 0


if __name__ == "__main__":
    sys.exit(main())

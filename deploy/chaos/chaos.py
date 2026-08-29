#!/usr/bin/env python3
"""The seeded loop.

One seed produces one exact sequence of operations and fault injections, so a
finding carries a way to make it happen again. After every operation the whole
invariant set runs; a violation is one line in findings.txt with the seed and
the step number that produced it.

    ./chaos.py --seed 4711 --steps 200
    ./chaos.py --seed 4711 --steps 200 --no-faults   # operations only
    ./chaos.py --seed 4711 --replay 137              # print the sequence, act on nothing

Everything it creates is called chaos-*; --cleanup removes the lot.
"""

import argparse
import json
import os
import random
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from invariants import (CLOUD, CLUSTER1, CLUSTER2, CLUSTERS, CLOUD_PORT, CLUSTER_PORT,
                        NODE_HOST, NODE_OF_CLUSTER, OUT, State, check, sh, items)
import ops
from ops import (cloud, cluster, vm_body, obj, cloud_vm, cluster_vm, phase_of,
                 wait_for, wait_gone, log, finding, ctl, kill_agent, start_agent,
                 kill_controller, kill_vmm, cleanup)

OPS = ["create", "create", "create", "delete", "stop", "start", "volume",
       "floating", "label", "cordon", "tenant"]
FAULTS = ["agent-kill", "vmm-kill", "replica-kill", "cloud-kill", "agent-stop"]


class World:
    """What the loop believes it made. Never the source of truth — the API is."""

    def __init__(self, rnd):
        self.rnd = rnd
        self.vms = []          # (tier, cluster, name)
        self.tenants = []
        self.pools = []
        self.fips = []
        self.n = 0

    def fresh(self, kind):
        self.n += 1
        return f"chaos-{kind}-{self.n}"


def do_create(w, seed, step):
    tier = w.rnd.choice(["cloud", "cluster", "cluster"])
    cn = w.rnd.choice(list(CLUSTERS))
    name = w.fresh("vm")
    kw = dict(mem=w.rnd.choice([160, 192, 256, 320]), vcpus=1)
    if w.tenants and w.rnd.random() < 0.35:
        kw["tenant"] = w.rnd.choice(w.tenants)
        tier = "cloud"          # tenant is a cloud-tier field
    if w.rnd.random() < 0.30:
        grp = f"g{w.rnd.randrange(3)}"
        kw["labels"] = {"grp": grp}
        kw["anti"] = [{"selector": {"grp": grp}, "required": w.rnd.random() < 0.6}]
    if tier == "cloud":
        c, b = cloud("POST", "/vms", vm_body(name, **kw))
    else:
        c, b = cluster(cn, "POST", "/vms", vm_body(name, **kw))
    if c == 201:
        w.vms.append((tier, cn, name))
    return f"create {tier}/{cn} {name} {kw} -> {c}"


def do_delete(w, seed, step):
    if not w.vms:
        return "delete (nothing to delete)"
    tier, cn, name = w.vms.pop(w.rnd.randrange(len(w.vms)))
    c, _ = (cloud("DELETE", f"/vms/{name}") if tier == "cloud"
            else cluster(cn, "DELETE", f"/vms/{name}"))
    return f"delete {tier}/{cn} {name} -> {c}"


def _set_run(w, want):
    if not w.vms:
        return f"{want} (nothing there)"
    tier, cn, name = w.rnd.choice(w.vms)
    o = cloud_vm(name) if tier == "cloud" else cluster_vm(cn, name)
    if not o:
        return f"{want} {name} (gone)"
    o["spec"]["runStrategy"] = want
    c, b = (cloud("PUT", f"/vms/{name}", o) if tier == "cloud"
            else cluster(cn, "PUT", f"/vms/{name}", o))
    return f"runStrategy {name} -> {want} -> {c}"


def do_stop(w, seed, step):
    return _set_run(w, "Stopped")


def do_start(w, seed, step):
    return _set_run(w, "Running")


def do_volume(w, seed, step):
    cn = w.rnd.choice(list(CLUSTERS))
    name = w.fresh("vol")
    c, b = cluster(cn, "POST", "/volumes", obj("Volume", name,
                   {"sizeBytes": w.rnd.choice([16, 32, 64]) * 1024 * 1024}))
    if c != 201 and w.rnd.random() < 0.5:
        # delete a random existing one instead
        cc, bb = cluster(cn, "GET", "/volumes")
        mine = [o["metadata"]["name"] for o in items(bb) if o["metadata"]["name"].startswith("chaos-")]
        if mine:
            n = w.rnd.choice(mine)
            c2, _ = cluster(cn, "DELETE", f"/volumes/{n}")
            return f"volume delete {cn}/{n} -> {c2}"
    return f"volume create {cn}/{name} -> {c}"


def do_floating(w, seed, step):
    if not w.pools:
        pool = w.fresh("fpool")
        t = w.tenants[0] if w.tenants else None
        if not t:
            return "floating (no tenant yet)"
        c, b = cloud("POST", "/floatingpools", obj("FloatingPool", pool,
                     {"cidrs": ["203.0.113.0/28"], "quota": {t: 6}}))
        if c == 201:
            w.pools.append(pool)
        return f"floatingpool {pool} -> {c}"
    pool = w.rnd.choice(w.pools)
    t = w.rnd.choice(w.tenants)
    if w.fips and w.rnd.random() < 0.4:
        a = w.fips.pop(w.rnd.randrange(len(w.fips)))
        c, _ = cloud("DELETE", f"/floatingips/{a}")
        return f"floatingip release {a} -> {c}"
    c, b = cloud("POST", "/floatingips",
                 {"apiVersion": "meister.io/v1", "kind": "FloatingIp",
                  "metadata": {"name": ""}, "spec": {"pool": pool, "tenant": t}})
    if c == 201:
        w.fips.append(b["metadata"]["name"])
    return f"floatingip claim {pool}/{t} -> {c} {b['metadata']['name'] if c == 201 else ''}"


def do_label(w, seed, step):
    cn = w.rnd.choice(list(CLUSTERS))
    node = w.rnd.choice(NODE_OF_CLUSTER[cn])
    key = f"chaos-l{w.rnd.randrange(2)}"
    c, o = cluster(cn, "GET", f"/nodes/{node}")
    if c != 200:
        return f"label {node} -> GET {c}"
    lbl = o["spec"].setdefault("labels", {})
    if key in lbl:
        lbl.pop(key)
        what = "rm"
    else:
        lbl[key] = f"v{w.rnd.randrange(2)}"
        what = "set"
    c2, _ = cluster(cn, "PUT", f"/nodes/{node}", o)
    return f"label {what} {cn}/{node} {key} -> {c2}"


def do_cordon(w, seed, step):
    cn = w.rnd.choice(list(CLUSTERS))
    node = w.rnd.choice(NODE_OF_CLUSTER[cn])
    c, o = cluster(cn, "GET", f"/nodes/{node}")
    if c != 200:
        return f"cordon {node} -> GET {c}"
    o["spec"]["schedulable"] = not o["spec"].get("schedulable", True)
    c2, _ = cluster(cn, "PUT", f"/nodes/{node}", o)
    return f"cordon {cn}/{node} schedulable={o['spec']['schedulable']} -> {c2}"


def do_tenant(w, seed, step):
    if w.tenants and w.rnd.random() < 0.3:
        t = w.tenants.pop(w.rnd.randrange(len(w.tenants)))
        c, _ = cloud("DELETE", f"/tenants/{t}")
        if c not in (200, 204):
            w.tenants.append(t)
        return f"tenant delete {t} -> {c}"
    t = w.fresh("ten")
    q = {}
    if w.rnd.random() < 0.5:
        q = {"maxVms": w.rnd.randrange(1, 5), "maxMemMib": w.rnd.choice([512, 1024])}
    c, b = cloud("POST", "/tenants", obj("Tenant", t, {"description": "chaos", "quota": q}))
    if c == 201:
        w.tenants.append(t)
    return f"tenant create {t} quota={q} -> {c}"


def inject(w, seed, step):
    what = w.rnd.choice(FAULTS)
    if what == "agent-kill":
        cn = w.rnd.choice(list(CLUSTERS))
        node = w.rnd.choice([n for n in NODE_OF_CLUSTER[cn] if NODE_HOST.get(n)])
        kill_agent(node)
        return f"FAULT agent SIGKILL {node}"
    if what == "agent-stop":
        cn = w.rnd.choice(list(CLUSTERS))
        node = w.rnd.choice([n for n in NODE_OF_CLUSTER[cn] if NODE_HOST.get(n)])
        ops.stop_agent(node)
        time.sleep(w.rnd.randrange(10, 40))
        start_agent(node)
        return f"FAULT agent stop/start {node}"
    if what == "vmm-kill":
        cands = [(t, c, n) for (t, c, n) in w.vms]
        if not cands:
            return "FAULT vmm-kill (no vm)"
        tier, cn, name = w.rnd.choice(cands)
        o = cloud_vm(name) if tier == "cloud" else cluster_vm(cn, name)
        if not o:
            return "FAULT vmm-kill (vm gone)"
        # find where it actually runs
        for c2 in CLUSTERS:
            co = cluster_vm(c2, name)
            if co and co.get("spec", {}).get("nodeName"):
                kill_vmm(co["spec"]["nodeName"], co["metadata"]["uid"])
                return f"FAULT vmm SIGKILL {name} on {co['spec']['nodeName']}"
        return "FAULT vmm-kill (unbound)"
    if what == "replica-kill":
        ip = w.rnd.choice(CLUSTER1)
        kill_controller(ip, "meister-cluster-controller")
        return f"FAULT cluster replica SIGKILL {ip}"
    if what == "cloud-kill":
        ip = w.rnd.choice(CLOUD)
        kill_controller(ip, "meister-cloud-controller")
        return f"FAULT cloud replica SIGKILL {ip}"
    return "FAULT none"


VERBS = {"create": do_create, "delete": do_delete, "stop": do_stop, "start": do_start,
         "volume": do_volume, "floating": do_floating, "label": do_label,
         "cordon": do_cordon, "tenant": do_tenant}


def heal(w):
    """Put the fleet back into a shape the next step can be judged against."""
    for ip in CLUSTER1 + CLUSTER2:
        ctl(ip, "systemctl is-active meister-cluster-controller >/dev/null || "
                "systemctl start meister-cluster-controller")
    for ip in CLOUD:
        ctl(ip, "systemctl is-active meister-cloud-controller >/dev/null || "
                "systemctl start meister-cloud-controller")
    for cn in CLUSTERS:
        for node in NODE_OF_CLUSTER[cn]:
            if NODE_HOST.get(node):
                sh(node, "systemctl is-active meister-agent >/dev/null || "
                         "systemctl start meister-agent")
    # nothing stays cordoned between steps
    for cn in CLUSTERS:
        for node in NODE_OF_CLUSTER[cn]:
            c, o = cluster(cn, "GET", f"/nodes/{node}")
            if c == 200 and not o["spec"].get("schedulable", True):
                o["spec"]["schedulable"] = True
                cluster(cn, "PUT", f"/nodes/{node}", o)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--steps", type=int, default=100)
    ap.add_argument("--fault-every", type=int, default=12)
    ap.add_argument("--no-faults", action="store_true")
    ap.add_argument("--settle", type=float, default=6.0)
    ap.add_argument("--replay", type=int, default=0)
    ap.add_argument("--cleanup", action="store_true")
    a = ap.parse_args()

    if a.cleanup:
        print(json.dumps(cleanup(), indent=1))
        return 0

    rnd = random.Random(a.seed)
    w = World(rnd)
    if a.replay:
        for i in range(1, a.replay + 1):
            print(f"{i:4} {rnd.choice(OPS)}")
        return 0

    base = json.load(open(os.path.join(OUT, "baseline.json")))
    seq = os.path.join(OUT, f"seq-{a.seed}.log")
    log(f"seed {a.seed}, {a.steps} steps, fault every {a.fault_every}", f"seq-{a.seed}.log")

    for step in range(1, a.steps + 1):
        verb = rnd.choice(OPS)
        try:
            told = VERBS[verb](w, a.seed, step)
        except ops.ApiError as e:
            told = f"{verb} -> transport {e}"
        except Exception as e:
            told = f"{verb} -> harness {type(e).__name__}: {e}"
        line = f"{step:4} {told}"
        with open(seq, "a") as fh:
            fh.write(line + "\n")

        if not a.no_faults and step % a.fault_every == 0:
            try:
                fl = inject(w, a.seed, step)
            except Exception as e:
                fl = f"FAULT harness {type(e).__name__}: {e}"
            with open(seq, "a") as fh:
                fh.write(f"{step:4} {fl}\n")
            time.sleep(20)
            heal(w)
            time.sleep(25)

        time.sleep(a.settle)
        try:
            st = State()
            viol = check(st, base)
        except Exception as e:
            viol = [("HARNESS", f"the checker itself failed: {type(e).__name__}: {e}")]
        for fid, msg in viol:
            finding(fid, f"step{step}", a.seed, msg)
        if step % 10 == 0:
            print(f"  step {step}/{a.steps}  vms={len(w.vms)} tenants={len(w.tenants)} "
                  f"fips={len(w.fips)}", flush=True)

    heal(w)
    print(f"seed {a.seed} finished; sequence in {seq}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""The matrix of the chaos-extrem brief: one link, one condition, one load.

    ./matrix.py --link A --cond L200 --load w1 --seed 4714
    ./matrix.py --link A --cond D    --load w5 --seed 4715
    ./matrix.py --link A --cond none --load w1 --seed 4713   # the control row

A cell is (link, condition, load). The condition goes on the wire, the load
runs under it, and the numbers come out as one line in `out/matrix.txt` plus a
JSON blob in `out/matrix-<link>-<cond>-<load>-<seed>.json`.

Why this does not call `chaos.py --no-faults`: the brief wants p50/p99 of
Create -> Running with n >= 20 per cell, and chaos.py logs operations rather
than timing them. Everything it would give us we would have to parse back out
of a log. The loop below is the same four operations with a clock on them.

Every cell lifts its own shaping in a `finally`, and `unshape_all()` runs at
the end regardless -- a cell that dies must not leave a node behind. The
self-lift timer inside `shape()` is the second belt.
"""

import argparse
import json
import os
import statistics
import time

import ops
from ops import log, finding

OUT = ops.OUT
TENANT = "chaos-matrix"


def pct(xs, p):
    if not xs:
        return None
    xs = sorted(xs)
    k = (len(xs) - 1) * p
    lo, hi = int(k), min(int(k) + 1, len(xs) - 1)
    return round(xs[lo] + (xs[hi] - xs[lo]) * (k - lo), 2)


def scheduler_conflicts():
    """The counter the brief asks for, summed over the cluster-1 replicas."""
    total = 0
    for ip in ops.CLUSTER1:
        rc, out = ops.ctl(ip, "curl -sf localhost:9101/metrics 2>/dev/null | "
                              "grep '^meister_scheduler_conflicts_total' | awk '{print $2}'")
        for line in out.split():
            try:
                total += int(float(line))
            except ValueError:
                pass
    return total


def ensure_tenant():
    c, _ = ops.cloud("GET", f"/tenants/{TENANT}")
    if c == 404:
        ops.cloud("POST", "/tenants", ops.obj(
            "Tenant", TENANT, {"description": "chaos-extrem matrix"}))


def w1(seed, n, cname="cluster-1"):
    """Create -> Running, then destroy. The cell's main number."""
    ensure_tenant()
    creates, deletes, failed, errors = [], [], 0, 0
    for i in range(n):
        name = f"chaos-m{seed}-{i:02d}"
        t0 = time.time()
        try:
            c, _ = ops.cloud("POST", "/vms", ops.vm_body(name, tenant=TENANT))
            if c >= 400:
                errors += 1
                continue
        except Exception:
            errors += 1
            continue
        ok, secs = ops.wait_for(
            lambda: True if ops.phase_of(ops.cloud_vm(name)) == "Running" else None, 180)
        if ok:
            creates.append(round(time.time() - t0, 3))
        else:
            failed += 1
            log(f"  w1 {name} never reached Running "
                f"(phase {ops.phase_of(ops.cloud_vm(name))})")
        t1 = time.time()
        ops.cloud("DELETE", f"/vms/{name}")
        if ops.wait_gone(name, 180)[0]:
            deletes.append(round(time.time() - t1, 3))
    return {"n": len(creates), "failed": failed, "errors": errors,
            "create_p50": pct(creates, .50), "create_p99": pct(creates, .99),
            "create_max": max(creates) if creates else None,
            "delete_p50": pct(deletes, .50),
            "samples": creates}


def w5(link, cond, seconds, cname="cluster-1"):
    """Detection: how fast does the cluster notice, and how fast is it back."""
    node = "agent-1a" if link in ("A", "V") else None
    if node is None:
        return {"skipped": f"w5 is a node-detection load; link {link} has no single node"}

    def ready():
        c, o = ops.cluster(cname, "GET", f"/nodes/{node}")
        return (o.get("status") or {}).get("ready") if isinstance(o, dict) else None

    if ready() is not True:
        return {"skipped": f"{node} was not Ready before the cell started"}

    ends, t0 = [], time.time()
    try:
        if cond == "D":
            ops.partition(node, ops.CLUSTER1, on=True)
            ends = ["__partition__"]
        else:
            ends = ops.shape_link(link, cond, seconds)
        gone, t_gone = ops.wait_for(lambda: True if ready() is False else None, 150)
        detect = round(t_gone, 1) if gone else None
        if not gone:
            finding("W5", f"{link}x{cond}", "-",
                    f"{node} stayed Ready 150 s into {cond}")
    finally:
        if ends == ["__partition__"]:
            ops.partition(node, ops.CLUSTER1, on=False)
        else:
            ops.unshape_all(ends)
    t1 = time.time()
    back, t_back = ops.wait_for(lambda: True if ready() is True else None, 180)
    return {"detect_s": detect, "return_s": round(t_back, 1) if back else None,
            "came_back": bool(back), "node": node}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--link", required=True, choices=["A", "C", "E1", "E2", "R", "V"])
    ap.add_argument("--cond", required=True)
    ap.add_argument("--load", required=True, choices=["w1", "w5"])
    ap.add_argument("--seed", type=int, required=True)
    ap.add_argument("--n", type=int, default=20)
    ap.add_argument("--seconds", type=int, default=900)
    a = ap.parse_args()

    cell = f"{a.link}x{a.cond}x{a.load}"
    log(f"=== matrix {cell} seed={a.seed} ===")
    before = scheduler_conflicts()
    res, ends = {}, []
    t0 = time.time()
    try:
        if a.load == "w5":
            res = w5(a.link, a.cond, a.seconds)
        else:
            if a.cond == "D":
                ops.partition("agent-1a", ops.CLUSTER1, on=True)
                ends = ["__partition__"]
            elif a.cond != "none":
                ends = ops.shape_link(a.link, a.cond, a.seconds)
            res = w1(a.seed, a.n)
    finally:
        if ends == ["__partition__"]:
            ops.partition("agent-1a", ops.CLUSTER1, on=False)
        elif ends:
            ops.unshape_all(ends)
        ops.unshape_all()

    res.update({"cell": cell, "link": a.link, "cond": a.cond, "load": a.load,
                "seed": a.seed, "seconds": round(time.time() - t0, 1),
                "scheduler_conflicts_before": before,
                "scheduler_conflicts_after": scheduler_conflicts()})

    rc = os.system(f"{os.path.dirname(os.path.abspath(__file__))}/invariants.py "
                   f"--quiet --tag {cell} --seed {a.seed}")
    res["invariants_held"] = (rc == 0)

    with open(os.path.join(OUT, f"matrix-{cell}-{a.seed}.json"), "w") as f:
        json.dump(res, f, indent=1)
    line = (f"{cell}\tseed={a.seed}\tn={res.get('n', '-')}\t"
            f"p50={res.get('create_p50', res.get('detect_s', '-'))}\t"
            f"p99={res.get('create_p99', res.get('return_s', '-'))}\t"
            f"max={res.get('create_max', '-')}\t"
            f"failed={res.get('failed', '-')}\tinv={'ok' if res['invariants_held'] else 'BROKEN'}")
    with open(os.path.join(OUT, "matrix.txt"), "a") as f:
        f.write(line + "\n")
    print(line, flush=True)


if __name__ == "__main__":
    main()

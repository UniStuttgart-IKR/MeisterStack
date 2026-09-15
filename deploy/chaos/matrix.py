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
import re
import subprocess
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


def _ping_log(target, seconds, path):
    """Start a timestamped ping and return the Popen. Started BEFORE the fault,
    read after it: the gap between two successive replies is what the tenant
    actually felt, and you cannot measure it by asking afterwards."""
    fh = open(path, "w")
    return subprocess.Popen(["ping", "-D", "-i", "0.2", "-w", str(int(seconds)), target],
                            stdout=fh, stderr=subprocess.DEVNULL), fh


def _ping_gap(path):
    """(largest gap in seconds, replies seen). A ping that never came back at
    all is a gap of None, which is a different fact from a gap of zero."""
    ts = []
    with open(path) as fh:
        for line in fh:
            m = re.match(r"\[(\d+\.\d+)\].*icmp_seq=", line)
            if m:
                ts.append(float(m.group(1)))
    if len(ts) < 2:
        return None, len(ts)
    return round(max(b - a for a, b in zip(ts, ts[1:])), 2), len(ts)


def w2(seed, n=10, pool="fabric", tenant=None):
    """Provision -> Ready for volumes, and how many never get there."""
    tenant = tenant or TENANT
    ensure_tenant()
    ready, failed = [], 0
    for i in range(n):
        name = f"chaos-mv{seed}-{i:02d}"
        t0 = time.time()
        c, _ = ops.cloud("POST", "/volumes", {
            "apiVersion": "meister.io/v1", "kind": "Volume",
            "metadata": {"name": name, "tenant": tenant},
            "spec": {"pool": pool, "sizeGib": 1, "accessMode": "readWriteOnce"}})
        if c >= 400:
            failed += 1
            continue
        ok, _ = ops.wait_for(lambda: True if (ops.cloud("GET", f"/volumes/{name}")[1]
                                              .get("status", {}).get("phase")) == "Ready" else None, 180)
        if ok:
            ready.append(round(time.time() - t0, 3))
        else:
            failed += 1
        ops.cloud("DELETE", f"/volumes/{name}")
        ops.wait_for(lambda: True if ops.cloud("GET", f"/volumes/{name}")[0] == 404 else None, 120)
    return {"n": len(ready), "failed": failed, "pool": pool,
            "ready_p50": pct(ready, .50), "ready_p99": pct(ready, .99),
            "ready_max": max(ready) if ready else None, "samples": ready}


def w3(seed, rounds=3, tenant="lab", router="lab-out", fip="10.128.1.217"):
    """Router failover, both halves: the control plane's new activeNode, and
    the gap a packet from outside actually saw.

    The reference numbers this is measured against: 52.8 s on a hard poweroff
    (rollout-neutron), 4.4 s / 5.2 s on bare metal (blech-manacor).
    """
    control, data, notes = [], [], []
    for i in range(rounds):
        c, r = ops.cloud("GET", f"/routers/{router}?tenant={tenant}")
        if c >= 400:
            return {"skipped": f"router {router} not readable: {c}"}
        was = (r.get("status") or {}).get("activeNode")
        if not was:
            return {"skipped": "router has no activeNode"}
        plog = os.path.join(OUT, f"w3-ping-{seed}-{i}.log")
        proc, fh = _ping_log(fip, 120, plog)
        time.sleep(3)
        t0 = time.time()
        ops.stop_agent(was)
        log(f"  w3 round {i}: stopped the agent on {was}")

        def moved():
            _, o = ops.cloud("GET", f"/routers/{router}?tenant={tenant}")
            now = (o.get("status") or {}).get("activeNode")
            return now if now and now != was else None

        new, secs = ops.wait_for(moved, 150)
        if new:
            control.append(round(secs, 1))
            notes.append(f"{was} -> {new} in {secs:.1f}s")
        else:
            notes.append(f"{was} never handed over within 150 s")
            finding("W3", "failover", seed, f"{router} stayed on {was} 150 s after it stopped")
        time.sleep(8)
        proc.terminate()
        proc.wait(timeout=10)
        fh.close()
        gap, seen = _ping_gap(plog)
        data.append(gap)
        log(f"  w3 round {i}: control {control[-1] if new else '-'}s, "
            f"data gap {gap}s over {seen} replies")
        ops.start_agent(was)
        ops.wait_for(lambda: True if (ops.cluster("cluster-1", "GET", f"/nodes/{was}")[1]
                                      .get("status", {}).get("ready")) else None, 180)
    good = [d for d in data if d is not None]
    return {"n": len(control), "control_s": control, "data_gap_s": data,
            "control_p50": pct(control, .50), "control_max": max(control) if control else None,
            "data_p50": pct(good, .50), "data_max": max(good) if good else None,
            "notes": notes}


def w4(seed, node="agent-1a", cname="cluster-1"):
    """A VM with evacuation = restart, moved by `node drain`."""
    ensure_tenant()
    name = f"chaos-m4-{seed}"
    body = ops.vm_body(name, tenant=TENANT)
    body["spec"]["evacuation"] = "restart"
    body["spec"]["nodeName"] = node
    c, _ = ops.cloud("POST", "/vms", body)
    if c >= 400:
        return {"skipped": f"create refused: {c}"}
    ok, _ = ops.wait_for(lambda: True if ops.phase_of(ops.cloud_vm(name)) == "Running" else None, 180)
    if not ok:
        ops.cloud("DELETE", f"/vms/{name}")
        return {"skipped": "the VM never ran before the drain"}
    cli = os.path.join(os.path.dirname(os.path.dirname(
        os.path.dirname(os.path.abspath(__file__)))), "target/release/meister")
    t0 = time.time()
    subprocess.run([cli, "--config", "/mnt/vmstore/MeisterStack/cli.mtls.toml",
                    "node", "drain", node, "--cluster", cname],
                   capture_output=True, text=True, timeout=120)

    def elsewhere():
        _, o = ops.cluster(cname, "GET", f"/vms/{name}")
        st = o.get("status") or {}
        n = st.get("nodeName")
        return n if st.get("phase") == "Running" and n and n != node else None

    where, secs = ops.wait_for(elsewhere, 240)
    subprocess.run([cli, "--config", "/mnt/vmstore/MeisterStack/cli.mtls.toml",
                    "node", "uncordon", node, "--cluster", cname],
                   capture_output=True, text=True, timeout=60)
    ops.cloud("DELETE", f"/vms/{name}")
    if not where:
        finding("W4", "drain", seed, f"{name} did not move off {node} within 240 s")
    return {"moved_to": where, "drain_s": round(secs, 1) if where else None,
            "from": node}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--link", required=True, choices=["A", "C", "E1", "E2", "R", "V"])
    ap.add_argument("--cond", required=True)
    ap.add_argument("--load", required=True, choices=["w1", "w2", "w3", "w4", "w5"])
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
        elif a.load in ("w2", "w3", "w4"):
            if a.cond == "D":
                ops.partition("agent-1a", ops.CLUSTER1, on=True)
                ends = ["__partition__"]
            elif a.cond != "none":
                ends = ops.shape_link(a.link, a.cond, a.seconds)
            res = {"w2": lambda: w2(a.seed, a.n),
                   "w3": lambda: w3(a.seed),
                   "w4": lambda: w4(a.seed)}[a.load]()
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

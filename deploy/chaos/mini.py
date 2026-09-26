#!/usr/bin/env python3
"""Named transport, storage, drain and lifecycle measurements for the lab.

Use --list to inspect the catalogue; M0 checks discovery on every configured
controller endpoint. Other cases rely on the fixed topology and fixtures.
Most create mc-* resources, but M4 selects an existing stopped/Failed VM
without a prefix filter. Cleanup is best effort and not guaranteed on errors.

Scenario return values are findings plus measurement rows. Differences between
cluster-1 and cluster-2 do not isolate replica count from other fleet differences.
"""

import argparse
import json
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from invariants import (CLOUD, CLUSTERS, NODE_HOST, OUT, sh)
import mtls
import ops
from ops import cloud, cluster, vm_body, finding

SEED = os.environ.get("CHAOS_SEED", "-")
PREFIX = "mc-"
REG = {}

# The tenant every mini-chaos object belongs to. Made if missing, left behind
# only if a scenario dies mid-flight -- `--cleanup` takes it out.
TENANT = os.environ.get("MINI_TENANT", "mc-lab")


def scenario(sid, title):
    def deco(fn):
        fn.sid, fn.title = sid, title
        REG[sid] = fn
        return fn
    return deco


# --- small helpers -----------------------------------------------------------

def pct(xs, p):
    """Select a small-sample percentile with this helper's rounded-rank formula."""
    if not xs:
        return None
    s = sorted(xs)
    k = max(1, min(len(s), int(round(p / 100.0 * len(s) + 0.5))))
    return s[k - 1]


def summarise(name, xs):
    return {
        "scenario": name,
        "n": len(xs),
        "min": round(min(xs), 1) if xs else None,
        "p50": round(pct(xs, 50), 1) if xs else None,
        "p99": round(pct(xs, 99), 1) if xs else None,
        "max": round(max(xs), 1) if xs else None,
    }


def ensure_tenant():
    c, _ = cloud("GET", f"/tenants/{TENANT}")
    if c == 200:
        return
    cloud("POST", "/tenants", {
        "apiVersion": "meister.io/v1", "kind": "Tenant",
        "metadata": {"name": TENANT},
        "spec": {"description": "mini-chaos, wird abgeraeumt"},
    })


def vol_body(name, pool, gib=1):
    return {
        "apiVersion": "meister.io/v1", "kind": "Volume",
        "metadata": {"name": name},
        "spec": {"tenant": TENANT, "pool": pool, "sizeGib": gib},
    }


def wait_volume(name, want=("Ready",), bad=(), limit=180):
    """Wait for a cloud Volume to reach a phase. Returns (phase, seconds, saw).

    `saw` is every distinct phase on the way, in order -- the whole point of
    M1, where a volume reaches Ready THROUGH Failed and a client that only
    looks at the end never learns it.
    """
    t0 = time.time()
    saw = []
    while time.time() - t0 < limit:
        c, o = cloud("GET", f"/volumes/{name}")
        ph = (o.get("status") or {}).get("phase") if isinstance(o, dict) else None
        if ph and (not saw or saw[-1] != ph):
            saw.append(ph)
        if ph in want:
            return ph, time.time() - t0, saw
        if ph in bad:
            return ph, time.time() - t0, saw
        time.sleep(1)
    return (saw[-1] if saw else None), time.time() - t0, saw


def wait_vm(name, want=("Running",), limit=180):
    t0 = time.time()
    saw = []
    while time.time() - t0 < limit:
        c, o = cloud("GET", f"/vms/{name}")
        ph = (o.get("status") or {}).get("phase") if isinstance(o, dict) else None
        if ph and (not saw or saw[-1] != ph):
            saw.append(ph)
        if ph in want:
            return ph, time.time() - t0, saw
        time.sleep(1)
    return (saw[-1] if saw else None), time.time() - t0, saw


def drop_volume(name, limit=120):
    cloud("DELETE", f"/volumes/{name}")
    t0 = time.time()
    while time.time() - t0 < limit:
        c, _ = cloud("GET", f"/volumes/{name}")
        if c == 404:
            return True
        time.sleep(1)
    return False


def drop_vm(name, limit=120):
    cloud("DELETE", f"/vms/{name}")
    t0 = time.time()
    while time.time() - t0 < limit:
        c, _ = cloud("GET", f"/vms/{name}")
        if c == 404:
            return True
        time.sleep(1)
    return False


# ============================================================================
# M1 — a volume's road to Ready, on a three-replica tier and a one-replica one
# ============================================================================

@scenario("M1", "volume provision: 3-replica cluster vs 1-replica cluster")
def m1(reps=6):
    """Measure Ready latency and intervening Failed phases on two configured pools.

    This can expose replica-ownership failures; it does not establish their
    cause from timing alone. The pools are persistent lab fixtures.
    """
    ensure_tenant()
    f, rows = [], []
    for label, pool in (("cluster-1 (3 replicas)", "mc-fs"),
                        ("cluster-2 (1 replica)", "mc-fs2")):
        secs, poisoned = [], 0
        for i in range(reps):
            name = f"{PREFIX}m1-{i}"
            c, o = cloud("POST", "/volumes", vol_body(name, pool))
            if c not in (200, 201):
                f.append(("M1", f"{label}: create refused HTTP {c}: {str(o)[:160]}"))
                break
            ph, dt, saw = wait_volume(name)
            if ph != "Ready":
                f.append(("M1", f"{label}: {name} stopped at {ph} after {dt:.0f}s (saw {'->'.join(saw)})"))
            else:
                secs.append(dt)
                if "Failed" in saw:
                    poisoned += 1
            drop_volume(name)
        s = summarise(label, secs)
        s["through_Failed"] = f"{poisoned}/{len(secs)}"
        rows.append(s)
        if poisoned:
            f.append(("M1", f"{label}: {poisoned} of {len(secs)} volumes reached Ready "
                            f"THROUGH Failed; a provision the session-holding replica does "
                            f"in ~1 s took up to {max(secs):.0f} s"))
    return f, rows


# ============================================================================
# M0 — the harness reaches the tiers at all
# ============================================================================

@scenario("M0", "transport: every tier answers this harness on the wire it speaks")
def m0(reps=1):
    """Check transport, discovery kind and tier identity at every configured replica."""
    f, rows = [], []
    for label, addrs, port, tier in (
            [("cloud", CLOUD, ops.CLOUD_PORT, "cloud")]
            + [(name, addrs, ops.CLUSTER_PORT, "cluster")
               for name, addrs in sorted(CLUSTERS.items())]):
        for ip in addrs:
            row = {"endpoint": f"{ip}:{port}", "as": label, "scheme": mtls.scheme()}
            t0 = time.time()
            try:
                code, doc = ops.call(ip, port, "GET", "/apis/meister.io/v1")
            except ops.ApiError as e:
                # The wall. Named as a transport failure and not as anything
                # about the control plane, because that is exactly the
                # confusion this scenario exists to end.
                row["error"] = str(e)
                rows.append(row)
                f.append(("M0", f"{label} {ip}:{port}: the harness cannot speak to this "
                                f"endpoint at all ({e}); check CHAOS_CA/CHAOS_CERT/CHAOS_KEY "
                                f"and whether the tier serves {mtls.scheme()}"))
                continue
            row["http"] = code
            row["seconds"] = round(time.time() - t0, 3)
            if code != 200:
                rows.append(row)
                f.append(("M0", f"{label} {ip}:{port}: discovery answered HTTP {code}"))
                continue
            said = doc.get("tier") if isinstance(doc, dict) else None
            row["tier"] = said
            row["auth"] = doc.get("auth") if isinstance(doc, dict) else None
            rows.append(row)
            if not isinstance(doc, dict) or doc.get("kind") != "APIResourceList":
                f.append(("M0", f"{label} {ip}:{port}: answered 200 with something that is "
                                f"not a discovery document"))
            elif said != tier:
                f.append(("M0", f"{label} {ip}:{port}: calls itself {said!r}, and this "
                                f"harness has it down as a {tier}"))
    return f, rows


# ============================================================================
# M2 — detach says done, the VMM still holds the file
# ============================================================================

@scenario("M2", "hot-unplug: the control plane frees a disk the VMM still has open")
def m2(reps=1):
    """Compare observed detach state with matching VMM file descriptors on the node.

    The data disk is secondary so the boot-volume guard does not reject the
    edit. Failed reads and unchecked prerequisites can invalidate the result.
    """
    ensure_tenant()
    f, rows = [], []
    boot, data, vm = f"{PREFIX}m2-boot", f"{PREFIX}m2-vol", f"{PREFIX}m2-vm"
    for v in (boot, data):
        c, o = cloud("POST", "/volumes", vol_body(v, "mc-fs2"))
        if c not in (200, 201):
            return [("M2", f"volume create {v} refused HTTP {c}")], []
        ph, _, _ = wait_volume(v)
        if ph != "Ready":
            drop_volume(v)
            return [("M2", f"volume {v} never became Ready (stopped at {ph})")], []
    c, o = cloud("GET", f"/volumes/{data}")
    uid = o["metadata"]["uid"]
    node = (o.get("status") or {}).get("node")
    cloud("POST", "/vms", vm_body(vm, tenant=TENANT, volumes=[{"volume": boot}, {"volume": data}]))
    wait_vm(vm)
    # the data disk has to be open before a detach can prove anything
    for _ in range(30):
        c, o = cloud("GET", f"/volumes/{data}")
        if (o.get("status") or {}).get("openOn"):
            break
        time.sleep(2)
    _, out = sh(node, f"for p in $(pgrep -f '[c]loud-hypervisor'); do ls -l /proc/$p/fd 2>/dev/null; done | grep -c {uid}")
    open_before = out.strip()

    # detach through the cloud, then ask the node, not the API
    c, o = cloud("GET", f"/vms/{vm}")
    o["spec"]["vm"]["volumes"] = [{"volume": boot}]
    c, r = cloud("PUT", f"/vms/{vm}", o)
    if c != 200:
        f.append(("M2", f"detach PUT refused HTTP {c}: {str(r)[:160]}"))
    # give the control plane a minute to say the disk is closed, then look
    freed_at = None
    t0 = time.time()
    while time.time() - t0 < 60:
        c, o = cloud("GET", f"/volumes/{data}")
        st = o.get("status") or {}
        if not st.get("openOn") and not st.get("attachedTo"):
            freed_at = round(time.time() - t0, 1)
            break
        time.sleep(3)
    c, o = cloud("GET", f"/volumes/{data}")
    st = o.get("status") or {}
    _, out = sh(node, f"for p in $(pgrep -f '[c]loud-hypervisor'); do ls -l /proc/$p/fd 2>/dev/null; done | grep -c {uid}")
    open_after = out.strip()
    rows.append({"scenario": "detach", "node": node, "fd_before": open_before,
                 "fd_after": open_after, "status.attachedTo": st.get("attachedTo"),
                 "status.openOn": st.get("openOn"), "control_plane_freed_after_s": freed_at})
    if freed_at is not None and open_after != "0":
        f.append(("M2", f"the control plane freed the disk after {freed_at}s (attachedTo="
                        f"{st.get('attachedTo')!r}, openOn={st.get('openOn')!r}) but the vmm on "
                        f"{node} still holds {open_after} fd on {uid}; the next vm on this "
                        f"volume will die on ch's write lock"))
    drop_vm(vm)
    drop_volume(data)
    drop_volume(boot)
    return f, rows


# ============================================================================
# M3 — a finished drain reports that nothing moved
# ============================================================================

@scenario("M3", "drain: `moved` can never report a completed drain's work")
def m3(reps=1):
    """Compare drain progress with the two fixture VMs' observed locations.

    This edits node labels and drain state and assumes the fixed cluster-2
    topology. Restoration sets schedulable=true rather than restoring its
    original value, and is not protected by a finally block.
    """
    ensure_tenant()
    f, rows = [], []
    cname, node = "cluster-2", "agent-2a"
    stay, move = f"{PREFIX}m3-stay", f"{PREFIX}m3-move"
    # Pinned: this scenario drains agent-2a, so a VM the scheduler put
    # somewhere else would make the drain a no-op and the measurement a lie
    # about a machine it never touched. Pinned by a label and a nodeSelector
    # at the CLUSTER, because `spec.nodeName` is not a client's field at the
    # cloud (422 since the F20 fix) and nodeSelector is a cluster-tier field.
    c, o = cluster(cname, "GET", f"/nodes/{node}")
    o["spec"].setdefault("labels", {})["mc-m3"] = "here"
    c, o = cluster(cname, "PUT", f"/nodes/{node}", o)
    if c not in (200, 201):
        return [("M3", f"labelling {node} failed: HTTP {c}")], []
    for n in (stay, move):
        c, o = cluster(cname, "POST", "/vms", vm_body(n, node_sel={"mc-m3": "here"}))
        if c != 201:
            return [("M3", f"create {n} at {cname}: HTTP {c} {str(o)[:160]}")], []
        t0 = time.time()
        while time.time() - t0 < 180:
            c, o = cluster(cname, "GET", f"/vms/{n}")
            if (o.get("status") or {}).get("phase") == "Running":
                break
            time.sleep(2)
    c, o = cluster(cname, "GET", f"/vms/{move}")
    o["spec"]["evacuation"] = "restart"
    c, r = cluster(cname, "PUT", f"/vms/{move}", o)
    if c != 200:
        f.append(("M3", f"setting evacuation=restart on {move}: HTTP {c} {str(r)[:160]}"))

    c, o = cluster(cname, "GET", f"/nodes/{node}")
    where_before = {}
    for n in (stay, move):
        cc, oo = cluster(cname, "GET", f"/vms/{n}")
        where_before[n] = (oo.get("status") or {}).get("nodeName")
    # Everything on the machine, not just ours: `nested-1` lives there with
    # evacuation never, and a drain's `staying` counts it too.
    cc, oo = cluster(cname, "GET", "/vms")
    on_node_before = sum(1 for v in oo.get("items", [])
                         if (v.get("status") or {}).get("nodeName") == node)

    o["spec"]["drain"] = True
    cluster(cname, "PUT", f"/nodes/{node}", o)
    t0 = time.time()
    drained = None
    while time.time() - t0 < 180:
        c, o = cluster(cname, "GET", f"/nodes/{node}")
        d = (o.get("status") or {}).get("draining") or {}
        if d.get("complete"):
            drained = d
            break
        time.sleep(3)
    where_after = {}
    for n in (stay, move):
        cc, oo = cluster(cname, "GET", f"/vms/{n}")
        where_after[n] = (oo.get("status") or {}).get("nodeName")

    # "moved" is `movedTotal` since the proto addendum: cumulative, and what
    # this scenario was written to get. A VM that has LEFT the node counts,
    # whether or not it has landed anywhere yet.
    really_left = sum(1 for n in (stay, move)
                      if where_before[n] == node and where_after[n] != node)
    rows.append({"scenario": "drain", "seconds": round(time.time() - t0, 1),
                 "report": drained,
                 "really_left": really_left, "on_node_before": on_node_before,
                 "where": {k: (where_before[k], where_after[k]) for k in where_before}})
    if drained and drained.get("movedTotal", 0) != really_left:
        f.append(("M3", f"drain of {node} completed reporting movedTotal="
                        f"{drained.get('movedTotal', 0)} while {really_left} vm(s) actually "
                        f"left the node: {drained}"))
    if drained and drained.get("staying") != on_node_before - really_left:
        f.append(("M3", f"drain of {node} reports staying={drained.get('staying')} with "
                        f"{on_node_before - really_left} vm(s) still on it: {drained}"))

    # put the node back the way it was found
    c, o = cluster(cname, "GET", f"/nodes/{node}")
    o["spec"]["drain"] = False
    o["spec"]["schedulable"] = True
    (o["spec"].get("labels") or {}).pop("mc-m3", None)
    cluster(cname, "PUT", f"/nodes/{node}", o)
    for n in (stay, move):
        cluster(cname, "DELETE", f"/vms/{n}")
    t0 = time.time()
    while time.time() - t0 < 120:
        if all(cluster(cname, "GET", f"/vms/{n}")[0] == 404 for n in (stay, move)):
            break
        time.sleep(2)
    return f, rows


# ============================================================================
# M4 — the rescue that is refused because the rescue is needed
# ============================================================================

@scenario("M4", "reschedule is refused on exactly the phase that needs it")
def m4(reps=1):
    """Try releasing the binding of the first stopped-intent, Failed cloud VM.

    This mutates an existing VM without restricting selection to mc-* names.
    No suitable VM produces a skipped measurement.
    """
    f, rows = [], []
    c, o = cloud("GET", "/vms")
    failed = [i for i in (o.get("items") or [])
              if (i.get("status") or {}).get("phase") == "Failed"
              and i["spec"].get("runStrategy") == "Stopped"]
    if not failed:
        rows.append({"scenario": "reschedule-gate", "note":
                     "no stopped+Failed vm present; gate not exercised this run"})
        return f, rows
    vm = failed[0]
    name = vm["metadata"]["name"]
    body = json.loads(json.dumps(vm))
    body["spec"].pop("nodeName", None)
    body["spec"].pop("clusterName", None)
    c, o = cloud("PUT", f"/vms/{name}", body)
    rows.append({"scenario": "reschedule-gate", "vm": name,
                 "runStrategy": vm["spec"].get("runStrategy"),
                 "phase": "Failed", "http": c, "answer": str(o)[:200]})
    if c == 422 and "needs a stopped vm" in str(o):
        f.append(("M4", f"{name} is runStrategy=Stopped and phase=Failed, and reschedule "
                        f"refuses it with 'stop it first' -- there is no API path off a node "
                        f"that cannot execute commands"))
    return f, rows


# ============================================================================
# M5 — a node that is READY and cannot do anything
# ============================================================================

@scenario("M5", "liveness: READY is a heartbeat, not the ability to act")
def m5(reps=1):
    """Report recent database I/O errors on nodes currently marked Ready.

    Journal history is diagnostic evidence, not a present write/read health test.
    """
    f, rows = [], []
    for cname in CLUSTERS:
        c, o = cluster(cname, "GET", "/nodes")
        for n in (o.get("items") or []):
            name = n["metadata"]["name"]
            st = n.get("status") or {}
            if not st.get("ready"):
                continue
            # `sh` takes the NODE ID and maps it itself; manacor maps to None
            # (the workstation), which is a local shell and not this check's
            # business, so it is skipped by the same lookup.
            if NODE_HOST.get(name) in (None, "__missing__"):
                continue
            rc, out = sh(name, "journalctl -u meister-agent --since '-5 min' "
                               "--no-pager 2>/dev/null | grep -c 'Previous I/O error'")
            errs = out.strip() or "0"
            rc2, free = sh(name, "df -h / | tail -1 | awk '{print $4}'")
            rows.append({"node": name, "ready": True, "db_io_errors_5min": errs,
                         "free": free.strip()})
            if errs.isdigit() and int(errs) > 0:
                f.append(("M5", f"{name} reports READY and its agent cannot write: "
                                f"{errs} redb I/O errors in five minutes. The unit is active, "
                                f"the session beats, check.sh calls it green, and the "
                                f"scheduler keeps sending it work"))
    return f, rows


# ============================================================================
# M6 — convergence while a cluster replica reboots
# ============================================================================

@scenario("M6", "vm create convergence, with and without a replica reboot underneath")
def m6(reps=6):
    """Measure cloud VM creation under a caller-supplied experimental condition.

    MINI_UNDER labels the result. This function does not inject a reboot.
    """
    ensure_tenant()
    f, rows = [], []
    under = os.environ.get("MINI_UNDER", "steady state")
    secs = []
    for i in range(reps):
        name = f"{PREFIX}m6-{i}"
        t0 = time.time()
        c, o = cloud("POST", "/vms", vm_body(name, tenant=TENANT))
        if c not in (200, 201):
            f.append(("M6", f"create refused HTTP {c}: {str(o)[:160]}"))
            break
        ph, dt, saw = wait_vm(name)
        if ph == "Running":
            secs.append(dt)
        else:
            f.append(("M6", f"{name} stopped at {ph} after {dt:.0f}s (saw {'->'.join(saw)})"))
        drop_vm(name)
    rows.append(summarise(f"vm create -- {under}", secs))
    return f, rows


# --- cleanup -----------------------------------------------------------------

def cleanup():
    """Request deletion of mc-* VMs, volumes and snapshots at both tiers.

    Keep persistent mc-fs/mc-fs2 pool fixtures. Deletion results are not checked
    or awaited, and the tenant and node labels are not removed here.
    """
    gone = []
    for res in ("vms", "volumes", "volumesnapshots"):
        c, o = cloud("GET", f"/{res}")
        for i in (o.get("items") or []):
            n = i["metadata"]["name"]
            if n.startswith(PREFIX):
                cloud("DELETE", f"/{res}/{n}")
                gone.append(f"cloud/{res}/{n}")
    for cname in CLUSTERS:
        for res in ("vms", "volumes", "volumesnapshots"):
            c, o = cluster(cname, "GET", f"/{res}")
            if not isinstance(o, dict):
                continue
            for i in (o.get("items") or []):
                n = i["metadata"]["name"]
                if n.startswith(PREFIX):
                    cluster(cname, "DELETE", f"/{res}/{n}")
                    gone.append(f"{cname}/{res}/{n}")
    return gone


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ids", nargs="*")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--reps", type=int, default=6)
    ap.add_argument("--cleanup", action="store_true")
    a = ap.parse_args()

    if a.list:
        for sid in sorted(REG):
            print(f"{sid}  {REG[sid].title}")
        return 0
    if a.cleanup:
        for g in cleanup():
            print("removed", g)
        return 0

    print(f"transport: {mtls.describe()}", file=sys.stderr)
    ids = sorted(REG) if a.all else a.ids
    if not ids:
        ap.error("name a scenario, or --all, or --list")
    bad = 0
    for sid in ids:
        fn = REG.get(sid)
        if not fn:
            print(f"no such scenario: {sid}", file=sys.stderr)
            bad = 2
            continue
        print(f"\n=== {sid}  {fn.title} ===")
        try:
            f, rows = fn(a.reps) if fn.__code__.co_argcount else fn()
        except TypeError:
            f, rows = fn()
        for r in rows:
            print("   ", json.dumps(r, sort_keys=True))
        for fid, msg in f:
            print(f"    FINDING {fid}: {msg}")
            finding(fid, sid, SEED, msg)
        if f:
            bad = max(bad, 1)
    return bad


if __name__ == "__main__":
    sys.exit(main())

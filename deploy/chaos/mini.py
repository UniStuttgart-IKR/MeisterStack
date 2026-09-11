#!/usr/bin/env python3
"""The mini-chaos scenarios: what Image 58 added, on twelve real hosts.

The big loop in `chaos.py` walks a random sequence and judges it against the
invariants. This file is the other half the mini-chaos brief asked for: a
handful of named, repeatable measurements that each answer ONE question about
the storage, hot-plug, drain and reschedule work of the last week, with a
number rather than a verdict.

    ./mini.py --list
    ./mini.py M1
    ./mini.py --all
    ./mini.py M1 --reps 20

Every object it makes is called `mc-*`, the same prefix the run's report uses,
and every scenario tears its own down. Nothing here touches the evidence
(`cloud-probe`, `ubuntu-probe`, `nested-1`, `fleet-*`).

A scenario returns `(findings, table)`: findings are `(id, sentence)` pairs
that land in `out/findings.txt` exactly as the rest of the harness does it,
and the table is what gets typed into the report.

WHY THE MEASUREMENTS ARE PAIRED. Several of these run the same operation twice,
once against cluster-1 and once against cluster-2, and the pair IS the result:
cluster-1 has three controller replicas, cluster-2 has one. A number that is
bad on the first and clean on the second says "HA did this", which no single
measurement can say.
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
    """The p-th percentile of a small sample, nearest-rank.

    Nearest-rank and not interpolation: with ten samples an interpolated p99
    is a statement about a value that was never measured, and these samples
    are seconds off a lab, not a distribution anybody fitted.
    """
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
    """The measurement that names the HA bug.

    A `Volume` created at the cloud is reconciled by EVERY cluster-controller
    replica, but only the one holding the node's session can deliver
    `ProvisionVolume`. The other two reach `send_command`, get "node X has no
    active session" back from their LOCAL registry, and publish `Failed` --
    a phase whose own requeue curve then decides how long the volume sits
    there. Two of three passes therefore poison a provision that the third
    would have finished in a second.

    Run against cluster-2, which has one replica, the same volume is Ready
    without ever being Failed. That pair is the finding.
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
    """The cheapest measurement there is, and the one that was missing.

    The harness was written against a lab whose REST ports were plain http.
    Image 58 turned mTLS on, and every request died at the first byte with
    `ApiError HTTP 0: BadStatusLine:  2` — TLS answering an http client. It
    was not a scenario failing; it was the whole harness talking to a wall,
    and nothing said so until somebody read the exception.

    So: ask every endpoint for the one document that needs no objects, no
    tenant and no state — the discovery — and judge three things about the
    answer:

      * it came back at all, over the scheme this transport chose. A
        transport error here is THE finding, and it is the one that must not
        be reported as "the cloud refused" or "the volume was slow";
      * it is this API's discovery document, not a proxy's error page;
      * the tier calls itself what the harness thinks it is, so a run that
        has cloud and cluster the wrong way round says so on the first
        measurement rather than on the tenth.

    Every replica separately, not the first one: D2 was invisible until each
    was asked on its own.
    """
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
    """`vm detach` reports the volume free while cloud-hypervisor keeps the fd.

    The agent calls `vm.remove-device` and the CH API acknowledges the
    REQUEST; virtio unplug is guest-cooperative and a guest that never
    acknowledges leaves the device -- and the open file -- in place. Nothing
    verifies. The volume goes to `Ready / attachedTo: none`, and the next VM
    that uses it dies on cloud-hypervisor's own write lock, which is the only
    thing standing between this and two VMMs on one disk.

    Judged on the node, because the control plane is exactly the thing that
    is wrong here: `/proc/<vmm>/fd` is the only honest witness.
    """
    ensure_tenant()
    f, rows = [], []
    vol, vm = f"{PREFIX}m2-vol", f"{PREFIX}m2-vm"
    c, o = cloud("POST", "/volumes", vol_body(vol, "mc-fs2"))
    if c not in (200, 201):
        return [("M2", f"volume create refused HTTP {c}")], []
    ph, _, _ = wait_volume(vol)
    if ph != "Ready":
        drop_volume(vol)
        return [("M2", f"volume never became Ready (stopped at {ph})")], []
    c, o = cloud("GET", f"/volumes/{vol}")
    uid = o["metadata"]["uid"]
    node = (o.get("status") or {}).get("node")

    cloud("POST", "/vms", vm_body(vm, tenant=TENANT, volumes=[{"volume": vol}]))
    wait_vm(vm)
    _, out = sh(node, f"for p in $(pgrep -f '[c]loud-hypervisor'); do ls -l /proc/$p/fd 2>/dev/null; done | grep -c {uid}")
    open_before = out.strip()

    # detach through the cloud, then ask the node, not the API
    c, o = cloud("GET", f"/vms/{vm}")
    o["spec"]["vm"]["volumes"] = []
    cloud("PUT", f"/vms/{vm}", o)
    time.sleep(15)
    c, o = cloud("GET", f"/volumes/{vol}")
    attached = (o.get("status") or {}).get("attachedTo")
    _, out = sh(node, f"for p in $(pgrep -f '[c]loud-hypervisor'); do ls -l /proc/$p/fd 2>/dev/null; done | grep -c {uid}")
    open_after = out.strip()
    rows.append({"scenario": "detach", "node": node, "fd_before": open_before,
                 "fd_after": open_after, "status.attachedTo": attached})
    if open_after != "0":
        f.append(("M2", f"detach reported done (attachedTo={attached!r}) but the vmm on "
                        f"{node} still holds {open_after} fd on {uid}; the next vm on this "
                        f"volume will die on ch's write lock"))
    drop_vm(vm)
    drop_volume(vol)
    return f, rows


# ============================================================================
# M3 — a finished drain reports that nothing moved
# ============================================================================

@scenario("M3", "drain: `moved` can never report a completed drain's work")
def m3(reps=1):
    """`status.draining.moved` is a per-pass counter, `complete` is `moved == 0`.

    The field says "VMs this drain has got off the machine, or is getting off
    it", and the reconciler counts, in ONE pass, the VMs it still has to move.
    A VM that has left is no longer among the node's VMs, so it stops being
    counted -- and `complete = settled && moved == 0` cannot be true unless
    `moved` is zero. The two fields are mutually exclusive by construction, so
    a finished drain always reads `moved: 0`, whatever it did.

    Set up on cluster-2 so the evidence (`nested-1`, evacuation never) is the
    third kind of VM without being touched.
    """
    ensure_tenant()
    f, rows = [], []
    cname, node = "cluster-2", "agent-2a"
    stay, move = f"{PREFIX}m3-stay", f"{PREFIX}m3-move"
    for n in (stay, move):
        # Pinned: this scenario drains agent-2a, so a VM the scheduler put
        # somewhere else would make the drain a no-op and the measurement a
        # lie about a machine it never touched.
        body = vm_body(n, tenant=TENANT, cluster_name=cname)
        body["spec"]["nodeName"] = node
        cloud("POST", "/vms", body)
        wait_vm(n)
    c, o = cloud("GET", f"/vms/{move}")
    o["spec"]["evacuation"] = "restart"
    cloud("PUT", f"/vms/{move}", o)

    c, o = cluster(cname, "GET", f"/nodes/{node}")
    where_before = {}
    for n in (stay, move):
        cc, oo = cluster(cname, "GET", f"/vms/{n}")
        where_before[n] = (oo.get("status") or {}).get("nodeName")

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

    really_moved = sum(1 for n in (stay, move)
                       if where_before[n] != where_after[n] and where_after[n])
    rows.append({"scenario": "drain", "seconds": round(time.time() - t0, 1),
                 "report.moved": (drained or {}).get("moved"),
                 "report.staying": (drained or {}).get("staying"),
                 "really_moved": really_moved,
                 "where": {k: (where_before[k], where_after[k]) for k in where_before}})
    if drained and drained.get("moved") == 0 and really_moved > 0:
        f.append(("M3", f"drain of {node} completed reporting moved=0 while {really_moved} "
                        f"vm(s) actually changed node; `complete` is defined as `moved == 0`, "
                        f"so the field can never report a finished drain's work"))

    # put the node back the way it was found
    c, o = cluster(cname, "GET", f"/nodes/{node}")
    o["spec"]["drain"] = False
    o["spec"]["schedulable"] = True
    cluster(cname, "PUT", f"/nodes/{node}", o)
    for n in (stay, move):
        drop_vm(n)
    return f, rows


# ============================================================================
# M4 — the rescue that is refused because the rescue is needed
# ============================================================================

@scenario("M4", "reschedule is refused on exactly the phase that needs it")
def m4(reps=1):
    """`reschedule` gates on `status.phase == Stopped`.

    A VM whose node cannot execute commands sits at `Failed`. It will never
    reach `Stopped`, because reaching `Stopped` is a thing that node would
    have to do. So the one API call that would move it to a working machine
    is refused, and the refusal tells the operator to do what they already
    did -- `spec.runStrategy` is `Stopped` throughout.

    Same gate in both tiers:
      components/cloud-controller/src/api/vms.rs::reschedule_refusal
      components/cluster-controller/src/api.rs::check_reschedule

    This scenario does not break a node to prove it. It reads the gate against
    a VM that is Failed for any reason, which is the condition that matters.
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
    """The invariant the fleet had no check for.

    An agent whose redb has taken one I/O error answers `begin write:
    Previous I/O error occurred. Please close and re-open the database.` to
    every command, for ever -- redb requires a reopen and the agent never does
    one. The session keeps beating, the unit stays `active`, `node ls` says
    READY, and `deploy/check.sh` says green, because none of those touch the
    database.

    So the scheduler keeps placing work on it, and every placement fails.

    This is a check, not an injection: it reads each READY node's journal and
    reports any that is lying about being able to work.
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
    """Position 4's number: does losing one of three replicas cost anything?

    Measured as time from `POST /vms` to `status.phase == Running` at the
    cloud, which is the only latency a user of this thing ever sees. The
    reboot half is driven from `one.py` and is the caller's job to start --
    this scenario measures, it does not reboot, because a scenario that
    reboots a controller replica should be a deliberate keystroke.

    Set MINI_UNDER='what is happening' to label the run.
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
    """Every mc-* object on both tiers, and the tenant."""
    gone = []
    for res in ("vms", "volumes", "volumesnapshots"):
        c, o = cloud("GET", f"/{res}")
        for i in (o.get("items") or []):
            n = i["metadata"]["name"]
            if n.startswith(PREFIX):
                cloud("DELETE", f"/{res}/{n}")
                gone.append(f"cloud/{res}/{n}")
    for cname in CLUSTERS:
        for res in ("vms", "volumes", "volumesnapshots", "storagepools"):
            c, o = cluster(cname, "GET", f"/{res}")
            if not isinstance(o, dict):
                continue
            for i in (o.get("items") or []):
                n = i["metadata"]["name"]
                if n.startswith(PREFIX):
                    cluster(cname, "DELETE", f"/{res}/{n}")
                    gone.append(f"{cname}/{res}/{n}")
    c, o = cloud("GET", "/storagepools")
    for i in (o.get("items") or []):
        n = i["metadata"]["name"]
        if n.startswith(PREFIX):
            cloud("DELETE", f"/storagepools/{n}")
            gone.append(f"cloud/storagepools/{n}")
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

#!/usr/bin/env python3
"""The verbs. Everything the chaos loop and the scenario catalog can do to the
lab, and nothing that judges the result — judging is invariants.py's job.

Blackbox on purpose: the REST tiers and a shell on the nodes, no product code.
"""

import json
import os
import random
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request

from invariants import (CLOUD, CLUSTER1, CLUSTER2, CLUSTERS, CLOUD_PORT, CLUSTER_PORT,
                        NODE_HOST, NODE_OF_CLUSTER, OUT, SSH, sh, get, items)
import mtls

V1 = "/apis/meister.io/v1"


class ApiError(Exception):
    def __init__(self, code, body):
        super().__init__(f"HTTP {code}: {body[:400]}")
        self.code = code
        self.body = body


def call(ip, port, method, path, body=None, timeout=20):
    # Names travel in the path and the lab accepts names a path cannot hold
    # verbatim; quote the last segment so the CLIENT is never the thing that
    # fails when the server took something odd.
    head, sep, tail = path.rpartition("/")
    if sep and tail:
        path = head + sep + urllib.parse.quote(tail, safe="")
    url = f"{mtls.scheme()}://{ip}:{port}{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data:
        req.add_header("Content-Type", "application/json")
    try:
        # Not `urllib.request.urlopen`: since Image 58 both tiers want a
        # client certificate, and the default opener has none.
        with mtls.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode()
            return r.status, (json.loads(raw) if raw.strip() else {})
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
    except Exception as e:
        raise ApiError(0, f"{type(e).__name__}: {e}")


def cloud(method, path, body=None, ip=None, timeout=20):
    return call(ip or CLOUD[0], CLOUD_PORT, method, V1 + path, body, timeout)


def cluster(cname, method, path, body=None, ip=None, timeout=20):
    return call(ip or CLUSTERS[cname][0], CLUSTER_PORT, method, V1 + path, body, timeout)


# --- object factories --------------------------------------------------------

def vm_body(name, vcpus=1, mem=256, tenant=None, labels=None, node_sel=None,
            cluster_sel=None, anti=None, run="Running", volumes=None, nics=None,
            cluster_name=None):
    meta = {"name": name}
    if labels:
        meta["labels"] = labels
    sp = {
        "runStrategy": run,
        "vm": {
            "vcpus": vcpus,
            "memory_mib": mem,
            "boot": {"kind": "direct_kernel", "kernel": "vmlinux.elf",
                     "initramfs": "tiny-initrd", "cmdline": "console=ttyS0 rdinit=/init"},
            "volumes": volumes if volumes is not None
                       else [{"base_image": "tiny-volume.raw", "size_bytes": 67108864}],
            "nics": nics or [],
            "devices": [],
        },
    }
    if tenant:
        sp["tenant"] = tenant
    if node_sel:
        sp["nodeSelector"] = node_sel
    if cluster_sel:
        sp["clusterSelector"] = cluster_sel
    if anti:
        sp["antiAffinity"] = anti
    if cluster_name:
        sp["clusterName"] = cluster_name
    return {"apiVersion": "meister.io/v1", "kind": "Vm", "metadata": meta, "spec": sp}


def obj(kind, name, spec, labels=None):
    meta = {"name": name}
    if labels:
        meta["labels"] = labels
    return {"apiVersion": "meister.io/v1", "kind": kind, "metadata": meta, "spec": spec}


# --- waiting ----------------------------------------------------------------

def wait_for(fn, timeout=90, step=2):
    """Poll fn() until it returns truthy. Returns (value, seconds) or (None, t)."""
    t0 = time.time()
    while time.time() - t0 < timeout:
        val = fn()
        if val:
            return val, time.time() - t0
        time.sleep(step)
    return None, time.time() - t0


def cloud_vm(name, ip=None):
    c, b = cloud("GET", f"/vms/{name}", ip=ip)
    return b if c == 200 else None


def cluster_vm(cname, name, ip=None):
    c, b = cluster(cname, "GET", f"/vms/{name}", ip=ip)
    return b if c == 200 else None


def phase_of(o):
    return ((o or {}).get("status") or {}).get("phase")


def wait_phase(name, want, timeout=120, where="cloud", cname="cluster-1"):
    getter = (lambda: cloud_vm(name)) if where == "cloud" else (lambda: cluster_vm(cname, name))
    return wait_for(lambda: (lambda o: o if phase_of(o) == want else None)(getter()), timeout)


def wait_gone(name, timeout=180, where="cloud", cname="cluster-1"):
    getter = (lambda: cloud_vm(name)) if where == "cloud" else (lambda: cluster_vm(cname, name))
    return wait_for(lambda: getter() is None, timeout)


# --- fleet manipulation ------------------------------------------------------

def kill_agent(node, sig="KILL"):
    return sh(node, f"systemctl show -p MainPID --value meister-agent | xargs -r kill -{sig}")


def stop_agent(node):
    return sh(node, "systemctl stop meister-agent")


def start_agent(node):
    return sh(node, "systemctl start meister-agent")


def kill_controller(ip, unit, sig="KILL"):
    argv = SSH + [f"root@{ip}", f"systemctl show -p MainPID --value {unit} | xargs -r kill -{sig}"]
    p = subprocess.run(argv, capture_output=True, text=True, timeout=25)
    return p.returncode, p.stdout


def ctl(ip, cmd, timeout=30):
    argv = SSH + [f"root@{ip}", cmd]
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout + p.stderr
    except subprocess.TimeoutExpired:
        return 124, ""


def kill_vmm(node, vm_uid):
    """Kill the cloud-hypervisor process that serves one VM."""
    return sh(node, f"ps -eo pid,args --no-headers | grep '[c]loud-hypervisor' | "
                    f"grep '{vm_uid}' | awk '{{print $1}}' | xargs -r kill -9")


def partition(node, peer_ips, on=True, port=50051):
    """Blackhole (DROP, not reject) this node's control-plane traffic.

    nft and not iptables: the lab's agent VMs are NixOS and carry no iptables
    at all, so the first version of this silently did nothing and reported a
    partition that never happened. Only the session port is dropped, never a
    whole host — the ssh this harness rides on shares the wire.
    """
    ips = ", ".join(peer_ips)
    if on:
        cmd = (
            "nft add table inet chaos; "
            "nft add chain inet chaos out '{ type filter hook output priority 0; }'; "
            "nft add chain inet chaos inb '{ type filter hook input priority 0; }'; "
            f"nft add rule inet chaos out ip daddr {{ {ips} }} tcp dport {port} drop; "
            f"nft add rule inet chaos inb ip saddr {{ {ips} }} tcp sport {port} drop; "
            "nft list table inet chaos | grep -c drop"
        )
    else:
        cmd = "nft delete table inet chaos 2>/dev/null; echo lifted"
    return sh(node, cmd)


def log(msg, f="run.log"):
    line = f"{time.strftime('%H:%M:%S')} {msg}"
    with open(os.path.join(OUT, f), "a") as fh:
        fh.write(line + "\n")
    print(line, flush=True)


def finding(fid, tag, seed, msg):
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    with open(os.path.join(OUT, "findings.txt"), "a") as fh:
        fh.write(f"{stamp}\t{fid}\t{tag}\tseed={seed}\t{msg}\n")
    print(f"  ** {fid} {tag}: {msg}", flush=True)


def _mine(o, prefix):
    """Is this object one of ours?

    By NAME where the harness chose the name, and by the tenant or the pool
    where it did not -- which is the hole D-H2 was: a floating address is
    named after the ADDRESS (`198.51.100.1`), so the name filter skipped every
    one of them, the pool could then not be deleted because addresses were out
    of it, and the tenant could not be deleted because it held them. Three
    objects left standing, and `tenant rm` answering `409 ... still has
    floating addresses` to whoever cleaned up by hand afterwards.
    """
    meta, spec = o.get("metadata") or {}, o.get("spec") or {}
    for value in (meta.get("name"), spec.get("tenant"), spec.get("pool")):
        if isinstance(value, str) and value.startswith(prefix):
            return True
    return False


def cleanup(prefix="chaos-", passes=3, settle=15):
    """Delete every object this harness could have created, on both tiers.

    The ORDER is the rule and it is the reverse of how things are made: what
    holds something is deleted after the thing it holds. A tenant with a
    floating address, a pool with an address out of it and a storage pool with
    a volume in it each refuse to go, correctly -- so the cluster's objects go
    first, then the cloud's, and the tenants last.

    And then again, twice: a delete refused because a finalizer had not run
    yet succeeds on the second pass, which is cheaper than teaching this
    function every wait in the control plane. `passes` exists so a run that
    cleans nothing stops after one.

    **With time between them, which is what "on the second pass" assumes and
    which nothing here provided.** Three passes ran back-to-back in under two
    seconds, and tearing a guest down takes ten to twenty — so a refusal that
    a later pass was meant to survive met exactly the same estate each time.
    `settle` makes the sentence above true. It is NOT offered as the
    explanation of the one leak round 4's e2e saw: that run left
    `chaos-ten-35` standing, empty and deletable by hand a minute later, and
    probes at four, six and one vm — cloud tier and cluster tier — deleted
    their tenant on the first pass every time. What that leak was is written
    down and not closed.

    Which is why the second half of this exists: **what survives is named.**
    A cleanup that returns only what it killed reports a clean lab either
    way, and the leftover above was found by reading `tenant ls` afterwards
    rather than by anything here.
    """
    killed = []
    for attempt in range(passes):
        if attempt:
            time.sleep(settle)
        before = len(killed)
        # The cluster tier first: a volume holds a storage pool, and a VM
        # holds a volume.
        for cn in CLUSTERS:
            for res in ("vms", "volumesnapshots", "volumes", "storagepools"):
                c, b = cluster(cn, "GET", f"/{res}")
                if c != 200:
                    continue
                for o in items(b):
                    if not _mine(o, prefix):
                        continue
                    n = o["metadata"]["name"]
                    rc, _ = cluster(cn, "DELETE", f"/{res}/{n}")
                    if rc in (200, 202, 204, 404):
                        killed.append(f"{cn}/{res}/{n}")
        # Then the cloud's, tenants last: everything else is inside one.
        # Routers before their provider networks: a network that still
        # carries one refuses to go, exactly as a pool with reservations does.
        for res in ("vms", "volumes", "floatingips", "floatingpools",
                    "routers", "providernetworks",
                    "routedsubnets", "storagepools", "secrets", "images", "tenants"):
            c, b = cloud("GET", f"/{res}")
            if c != 200:
                continue
            for o in items(b):
                if not _mine(o, prefix):
                    continue
                n = o["metadata"]["name"]
                rc, _ = cloud("DELETE", f"/{res}/{n}")
                if rc in (200, 202, 204, 404):
                    killed.append(f"cloud/{res}/{n}")
        if len(killed) == before:
            break
    killed.extend(unlabel_nodes(prefix))
    for line in survivors(prefix):
        log(f"cleanup left behind: {line}")
    # Deduplicated, because a second pass re-lists what the first one asked
    # to delete: a 202 is "on its way out", not "gone".
    return sorted(set(killed))


def survivors(prefix="chaos-", settle=10):
    """Everything of this harness's that is still there after a cleanup.

    Asked once, after the passes and after a pause long enough for a `202` to
    become a `404`: an object on its way out is not a leak, and calling one
    would make this line noise that nobody reads.
    """
    time.sleep(settle)
    left = []
    for cn in CLUSTERS:
        for res in ("vms", "volumesnapshots", "volumes", "storagepools"):
            c, b = cluster(cn, "GET", f"/{res}")
            if c == 200:
                left += [f"{cn}/{res}/{o['metadata']['name']}"
                         for o in items(b) if _mine(o, prefix)]
    for res in ("vms", "volumes", "floatingips", "floatingpools", "routers",
                "providernetworks", "routedsubnets", "storagepools", "secrets",
                "images", "tenants"):
        c, b = cloud("GET", f"/{res}")
        if c == 200:
            left += [f"cloud/{res}/{o['metadata']['name']}"
                     for o in items(b) if _mine(o, prefix)]
    return sorted(left)


def unlabel_nodes(prefix="chaos-"):
    """Take this harness's labels off every node of every cluster.

    The other half of D-H2, and the one nothing was even trying to do:
    `chaos-l0` and `chaos-l1` were still stuck to all five agents after the
    run, and it was `meister-deploy check` that found them rather than the
    harness. A label is not an object, so no delete could ever have reached
    it -- it is a key in `spec.labels` and comes off with a patch that sets
    it to null.
    """
    taken = []
    for cn in CLUSTERS:
        c, b = cluster(cn, "GET", "/nodes")
        if c != 200:
            continue
        for node in items(b):
            name = node["metadata"]["name"]
            labels = ((node.get("spec") or {}).get("labels") or {})
            ours = [k for k in labels if k.startswith(prefix)]
            if not ours:
                continue
            rc, _ = cluster(cn, "PATCH", f"/nodes/{name}",
                            {"spec": {"labels": {k: None for k in ours}}})
            if rc in (200, 202):
                taken.extend(f"{cn}/nodes/{name}/labels/{k}" for k in ours)
    return taken

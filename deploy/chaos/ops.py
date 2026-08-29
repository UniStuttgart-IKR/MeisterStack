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
    url = f"http://{ip}:{port}{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
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


def cleanup(prefix="chaos-"):
    """Delete every object this harness could have created, on both tiers."""
    killed = []
    for res in ("vms", "floatingips", "floatingpools", "images", "tenants", "storagepools"):
        c, b = cloud("GET", f"/{res}")
        if c != 200:
            continue
        for o in items(b):
            n = o["metadata"]["name"]
            if n.startswith(prefix):
                cloud("DELETE", f"/{res}/{n}")
                killed.append(f"cloud/{res}/{n}")
    for cn in CLUSTERS:
        for res in ("vms", "volumes", "storagepools"):
            c, b = cluster(cn, "GET", f"/{res}")
            if c != 200:
                continue
            for o in items(b):
                n = o["metadata"]["name"]
                if n.startswith(prefix):
                    cluster(cn, "DELETE", f"/{res}/{n}")
                    killed.append(f"{cn}/{res}/{n}")
    return killed

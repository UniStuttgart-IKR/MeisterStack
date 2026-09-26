#!/usr/bin/env python3
"""REST requests, fixture operations and fault injection for the lab harness.

These helpers can mutate controller resources, services and host networking.
Topology, credentials and cleanup limits are documented in README.md.
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
    # Quote the final path segment without encoding the query delimiter.
    path, qsep, query = path.partition("?")
    head, sep, tail = path.rpartition("/")
    if sep and tail:
        path = head + sep + urllib.parse.quote(tail, safe="")
    path = path + qsep + query
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
        # Always a dict, never a bare string (D-H6). The success path returns a
        # parsed object and this one used to return text, so every caller that
        # forgot to check the code got `TypeError: string indices must be
        # integers` instead of a finding -- mini.py M3 died on exactly that and
        # took M4, M5 and M6 with it. `str(o)` still reads fine on a dict, which
        # is how every existing caller formats an error body.
        text = e.read().decode()
        msg = text
        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                msg = parsed.get("message") or parsed.get("error") or text
        except Exception:
            pass
        # Deliberately NOT the raw error envelope. The API answers errors with
        # `kind: Status`, and that envelope carries a top-level `status` field
        # whose value is the STRING "Failure" -- the same key a resource uses
        # for its status OBJECT. Handing it back verbatim makes every
        # `o.get("status").get("phase")` in this harness blow up one level
        # deeper than before, which is exactly what happened to mini.py's
        # wait_vm the first time this was fixed. `__error__` is the shape
        # invariants.py already uses for "this is not a resource".
        return e.code, {"__error__": text, "message": msg, "code": e.code}
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


# The getters return None for every non-200 response, so this currently treats
# HTTP failures as disappearance as well as 404.
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
    """Install nft DROP rules for this node's session traffic.

    Uses the shared inet chaos table; no automatic expiry is installed here.
    Inspect the returned status and remove the table after the experiment.
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


def partition_ip(ip, peer_ips, on=True, port=50050):
    """`partition` by address instead of node name: the controller replicas are
    not in NODE_HOST, and link C drops a cluster replica's session to the cloud."""
    ips = ", ".join(peer_ips)
    if on:
        cmd = ("nft add table inet chaos; "
               "nft add chain inet chaos out '{ type filter hook output priority 0; }'; "
               "nft add chain inet chaos inb '{ type filter hook input priority 0; }'; "
               f"nft add rule inet chaos out ip daddr {{ {ips} }} tcp dport {port} drop; "
               f"nft add rule inet chaos inb ip saddr {{ {ips} }} tcp sport {port} drop; "
               "nft list table inet chaos | grep -c drop")
    else:
        cmd = "nft delete table inet chaos 2>/dev/null; echo lifted"
    return ctl(ip, cmd)


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
    """Match object name, tenant or pool against a prefix.

    This is a naming convention, not proof that this run created the object.
    """
    meta, spec = o.get("metadata") or {}, o.get("spec") or {}
    for value in (meta.get("name"), spec.get("tenant"), spec.get("pool")):
        if isinstance(value, str) and value.startswith(prefix):
            return True
    return False


def cleanup(prefix="chaos-", passes=3, settle=15):
    """Attempt prefix-based deletion across selected cloud and cluster kinds.

    Repeat passes allow some finalizers to progress, then log survivors.
    A recorded DELETE acceptance is not proof that an object disappeared.
    Cloud snapshots, migration records and cluster routers are not enumerated.
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
    """List matching objects after a bounded settling delay.

    Only the enumerated kinds and successful API responses contribute results;
    an empty result does not establish complete cleanup.
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
    """Remove matching label keys from reachable cluster Node objects."""
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


# --- the shaper: Weg B, one NIC, the ports told apart on eth0 ----------------
#
# Position 0 of the chaos-extrem run measured the lab and found Weg A closed:
# only agent-1b and agent-1c carry an `eth1`, and it holds no IPv4 -- it is the
# router's provider NIC, not a MeisterStack path. Every controller has exactly
# `eth0`. So all of it -- sessions, etcd, REST, VXLAN and the ssh this harness
# rides on -- shares one wire, and the qdisc has to tell them apart by port.
#
# The shape is a `prio` root with every packet defaulting to band 2 (untouched)
# and a `u32` filter lifting only the named ports into band 3, which carries the
# netem. Port 22 can never be named; the guard below refuses it, because the
# harness would shape away its own hands. The NVMe-oF ports are refused for the
# same kind of reason: the brief puts that path out of bounds.

WIRE = "eth0"
NEVER_SHAPE = {22, 4421, 4422}          # ssh, and the storage path the brief protects
SHAPE_TOKEN = "/run/chaos-shape.token"

CONDS = {
    "L50":   ("netem", "delay 50ms 10ms"),
    "L200":  ("netem", "delay 200ms 10ms"),
    "L1000": ("netem", "delay 1000ms 10ms"),
    "P1":    ("netem", "loss 1%"),
    "P5":    ("netem", "loss 5%"),
    "P20":   ("netem", "loss 20%"),
    "J":     ("netem", "delay 200ms 150ms distribution normal"),
    "B10":   ("tbf",   "rate 10mbit burst 32kbit latency 400ms"),
}


def _on(where, cmd, timeout=40):
    """Run a shell command on a node name or on a bare IP."""
    if where in NODE_HOST:
        return sh(where, cmd, timeout=timeout)
    return ctl(where, cmd, timeout=timeout)


def _match(proto, side, port, peer=None):
    """One u32 clause. `side` is dport or sport -- the direction this end sees."""
    if port in NEVER_SHAPE:
        raise ValueError(f"refusing to shape port {port}: it is on the never-shape list")
    num = {"tcp": 6, "udp": 17}[proto]
    m = f"match ip protocol {num} 0xff match ip {side} {port} 0xffff"
    if peer:
        m += f" match ip dst {peer}/32"
    return m


def shape(where, cond, seconds, matches, wire=WIRE):
    """Replace the interface root qdisc and apply filters for the requested traffic.

    Validate the resulting qdisc/filter shape and request a systemd cleanup
    timer. Timer creation is not checked. Existing qdisc state is not saved.
    """
    if cond not in CONDS:
        raise ValueError(f"unknown condition {cond}; have {sorted(CONDS)}")
    kind, args = CONDS[cond]
    unit = f"chaos-unshape-{wire}"
    deadline = int(seconds) + 60
    parts = [
        f"systemctl stop {unit}.timer 2>/dev/null",
        f"systemctl reset-failed {unit}.timer {unit}.service 2>/dev/null",
        f"tc qdisc del dev {wire} root 2>/dev/null",
        f"tc qdisc add dev {wire} root handle 1: prio bands 3 "
        f"priomap 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1",
        f"tc qdisc add dev {wire} parent 1:3 handle 30: {kind} {args}",
    ]
    for i, m in enumerate(matches, start=1):
        parts.append(f"tc filter add dev {wire} protocol ip parent 1: prio {i} u32 {m} flowid 1:3")
    parts += [
        f"systemd-run --collect --on-active={deadline} --unit={unit} "
        f"tc qdisc del dev {wire} root >/dev/null 2>&1",
        f"echo FILTERS=$(tc filter show dev {wire} | grep -c flowid)",
        f"echo ROOT=$(tc qdisc show dev {wire} | head -1 | awk '{{print $2}}')",
        f"echo LEAF=$(tc qdisc show dev {wire} | sed -n 2p | awk '{{print $2}}')",
    ]
    rc, out = _on(where, "; ".join(parts))
    got = dict(l.split("=", 1) for l in out.split() if "=" in l and l.split("=")[0].isupper())
    n_want, n_got = len(matches), int(got.get("FILTERS", -1))
    if got.get("ROOT") != "prio" or got.get("LEAF") != kind or n_got != n_want:
        unshape(where, wire)
        raise RuntimeError(
            f"shape did not take on {where}: root={got.get('ROOT')} (want prio), "
            f"leaf={got.get('LEAF')} (want {kind}), filters={n_got} (want {n_want}). "
            f"raw: {out.strip()[:300]}")
    log(f"shape {where} {cond} [{kind} {args}] on {n_got} match(es), self-lift in {deadline}s")
    return rc, out


def unshape(where, wire=WIRE):
    """Delete the interface root qdisc and cleanup timer. Prior qdisc state is not restored."""
    unit = f"chaos-unshape-{wire}"
    return _on(where, f"systemctl stop {unit}.timer 2>/dev/null; "
                      f"systemctl reset-failed {unit}.timer {unit}.service 2>/dev/null; "
                      f"tc qdisc del dev {wire} root 2>/dev/null; echo lifted")


def shaped(where, wire=WIRE):
    """What is actually on the wire right now -- for the report, not for trust."""
    return _on(where, f"tc qdisc show dev {wire}; tc filter show dev {wire} | grep -c flowid")


# The six links of the matrix, as the ends that have to be shaped. A link is a
# list of (where, [match, ...]) -- more than one end when the condition has to
# bite in both directions.

def link_matches(link):
    a1a, a1b = NODE_HOST["agent-1a"], NODE_HOST["agent-1b"]
    if link == "A":       # one agent's session to its cluster
        return [("agent-1a", [_match("tcp", "dport", 50051, ip) for ip in CLUSTER1])]
    if link == "C":       # the replica that actually holds the voice
        who = voice_holder("cluster-1") or CLUSTER1[0]
        return [(who, [_match("tcp", "dport", 50050, ip) for ip in CLOUD])]
    if link == "E1":      # one etcd peer -- minority, raft holds
        peers = [ip for ip in CLUSTER1 if ip != CLUSTER1[0]]
        return [(CLUSTER1[0], [_match("tcp", "dport", 2380, ip) for ip in peers])]
    if link == "E2":      # two etcd peers -- majority gone, writes stall
        out = []
        for me in CLUSTER1[:2]:
            peers = [ip for ip in CLUSTER1 if ip != me]
            out.append((me, [_match("tcp", "dport", 2380, ip) for ip in peers]))
        return out
    if link == "R":       # the API as a client sees it.
        # Shaped at the CLOUD end on sport 3000, never on manacor: the brief
        # forbids changing manacor's interfaces, and a qdisc is a change.
        return [(CLOUD[0], [_match("tcp", "sport", 3000)])]
    if link == "G":       # whichever node actually holds the gateway right now
        # Not a fixed node: the active gateway moves, and a W3 cell that shapes
        # agent-1a while the router sits on agent-1c measures nothing at all.
        _, r = cloud("GET", "/routers/lab-out?tenant=lab")
        node = ((r.get("status") or {}).get("activeNode")) if isinstance(r, dict) else None
        if not node or node not in NODE_HOST:
            raise ValueError(f"link G: no usable activeNode on lab-out (got {node!r})")
        return [(node, [_match("tcp", "dport", 50051, ip) for ip in CLUSTER1])]
    if link == "V":       # the tenant overlay, agent to agent
        return [("agent-1a", [_match("udp", "dport", 4789, a1b)]),
                ("agent-1b", [_match("udp", "dport", 4789, a1a)])]
    raise ValueError(f"unknown link {link}; have A C E1 E2 G R V")


def shape_link(link, cond, seconds):
    """Shape every end of a link. Returns the list of ends, for unshaping."""
    ends = []
    for where, matches in link_matches(link):
        shape(where, cond, seconds, matches)
        ends.append(where)
    return ends


def unshape_all(ends=None):
    """Attempt qdisc removal on the given targets or the fixed fleet.

    Exceptions and remote return codes are not reflected in the returned list.
    """
    targets = ends if ends is not None else (
        list(NODE_HOST) + list(CLOUD) + list(CLUSTER1) + list(CLUSTER2))
    lifted = []
    for w in targets:
        try:
            unshape(w)
            lifted.append(w)
        except Exception:
            pass
    return lifted


def nft_drop(where, rules, on=True):
    """DROP the traffic `rules` names, on one end, with nft.

    `rules` are (proto, side, port, peer) like `_match`, so a D cell drops
    exactly what an L/P cell would have shaped. Never a whole host: ssh rides
    the same wire, and the never-shape list is honoured here too.
    """
    if not on:
        return _on(where, "nft delete table inet chaos 2>/dev/null; echo lifted")
    parts = ["nft add table inet chaos",
             "nft add chain inet chaos out '{ type filter hook output priority 0; }'",
             "nft add chain inet chaos inb '{ type filter hook input priority 0; }'"]
    for proto, side, port, peer in rules:
        if port in NEVER_SHAPE:
            raise ValueError(f"refusing to drop port {port}: never-shape list")
        d = "daddr" if side == "dport" else "saddr"
        peerpart = f"ip {d} {peer} " if peer else ""
        parts.append(f"nft add rule inet chaos out {peerpart}{proto} {side} {port} drop")
        back = "sport" if side == "dport" else "dport"
        d2 = "saddr" if side == "dport" else "daddr"
        peerpart2 = f"ip {d2} {peer} " if peer else ""
        parts.append(f"nft add rule inet chaos inb {peerpart2}{proto} {back} {port} drop")
    parts.append("nft list table inet chaos | grep -c drop")
    return _on(where, "; ".join(parts))


def voice_holder(cname="cluster-1"):
    """Return the first cluster replica with a matching established cloud connection.

    Multiple replicas may hold such connections; this is not authoritative
    evidence of the cloud registry's selected speaker.
    """
    peers = "|".join(CLOUD)
    for ip in CLUSTERS[cname]:
        rc, out = ctl(ip, f"ss -tn state established 2>/dev/null | "
                          f"grep -E ':{50050}' | grep -E '{peers}' | head -1")
        if out.strip():
            return ip
    return None


def link_drop_rules(link):
    """The (where, rules) a D cell has to drop, mirroring link_matches."""
    a1a, a1b = NODE_HOST["agent-1a"], NODE_HOST["agent-1b"]
    if link == "A":
        return [("agent-1a", [("tcp", "dport", 50051, ip) for ip in CLUSTER1])]
    if link == "C":
        who = voice_holder("cluster-1") or CLUSTER1[0]
        return [(who, [("tcp", "dport", 50050, ip) for ip in CLOUD])]
    if link == "E1":
        peers = [ip for ip in CLUSTER1 if ip != CLUSTER1[0]]
        return [(CLUSTER1[0], [("tcp", "dport", 2380, ip) for ip in peers])]
    if link == "E2":
        out = []
        for me in CLUSTER1[:2]:
            peers = [ip for ip in CLUSTER1 if ip != me]
            out.append((me, [("tcp", "dport", 2380, ip) for ip in peers]))
        return out
    if link == "G":
        _, r = cloud("GET", "/routers/lab-out?tenant=lab")
        node = ((r.get("status") or {}).get("activeNode")) if isinstance(r, dict) else None
        if not node or node not in NODE_HOST:
            raise ValueError(f"link G: no usable activeNode (got {node!r})")
        return [(node, [("tcp", "dport", 50051, ip) for ip in CLUSTER1])]
    if link == "R":
        return [(CLOUD[0], [("tcp", "sport", 3000, None)])]
    if link == "V":
        return [("agent-1a", [("udp", "dport", 4789, a1b)]),
                ("agent-1b", [("udp", "dport", 4789, a1a)])]
    raise ValueError(f"unknown link {link}")


def partition_link(link, on=True):
    """A D cell, on the link it names. Returns the ends it touched."""
    ends = []
    for where, rules in link_drop_rules(link):
        nft_drop(where, rules, on=on)
        ends.append(where)
    return ends


def unpartition(ends):
    for w in ends:
        try:
            nft_drop(w, [], on=False)
        except Exception:
            pass


def ping_rtt(frm, to, count=10):
    """Return the ping summary's average RTT in milliseconds, or None without a parsed reply."""
    rc, out = _on(frm, f"ping -c {count} -i 0.3 -W 3 {to} 2>/dev/null | tail -2")
    for line in out.splitlines():
        if "min/avg/max" in line or "rtt" in line:
            try:
                return float(line.split("=")[1].strip().split("/")[1])
            except Exception:
                pass
    return None

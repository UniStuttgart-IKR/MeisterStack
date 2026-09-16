#!/usr/bin/env python3
"""The invariant checker of the chaos brief.

Blackbox: everything here comes from the two REST tiers and from what a shell
on a node can see. No product code is imported, nothing is read out of etcd
directly. Every check is an assertion with a name; a violation is one line in
findings.txt and one line on stdout, nothing else.

    ./invariants.py                 # check once, print PASS/FAIL per invariant
    ./invariants.py --baseline      # record today's leftovers so leak checks
                                    # only ever report what THIS run created
    ./invariants.py --seed 1234     # stamp findings with the seed that made them
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mtls

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.environ.get("CHAOS_OUT", os.path.join(HERE, "out"))
os.makedirs(OUT, exist_ok=True)

# The phase rule lives in phases.py and is imported, not copied: I19 and
# `phases.py` on the command line have to agree, and two copies of a rule is
# how D-H4 happened. phases.py keeps its module level free of `ops` and of
# this file precisely so this import cannot close a cycle.
from phases import hole as phase_hole


def _addrs(name, default):
    """A comma-separated address list from the environment, or the lab's.

    The topology is the lab's and stays the lab's; what this adds is a way to
    point the harness somewhere else without editing it. `selftest.sh` needs
    exactly that — a stack on loopback that proves the harness can still
    reach a tier at all — and a self-test that had to patch this file would
    be a self-test nobody runs.
    """
    raw = os.environ.get(name)
    if raw is None:
        return default
    # SET AND EMPTY is a statement and not a fallback: a stack with one
    # cluster says `CHAOS_CLUSTER2=` and means it. Reading that as "use the
    # lab's" would send the self-test at an address nobody is listening on
    # and call it a finding.
    return [a.strip() for a in raw.split(",") if a.strip()]


CLOUD = _addrs("CHAOS_CLOUD", ["10.128.1.103", "10.128.1.112", "10.128.1.113"])
CLUSTER1 = _addrs("CHAOS_CLUSTER1", ["10.128.1.104", "10.128.1.110", "10.128.1.111"])
CLUSTER2 = _addrs("CHAOS_CLUSTER2", ["10.128.1.105"])
CLUSTERS = {"cluster-1": CLUSTER1, "cluster-2": CLUSTER2}
# A stack with one cluster is a real shape and the self-test's. Empty means
# "there is no cluster-2 here", not "cluster-2 is at no address".
CLUSTERS = {k: v for k, v in CLUSTERS.items() if v}
# node id -> how to reach a shell on it. manacor is the workstation itself.
NODE_HOST = {
    "agent-1a": "10.128.1.106",
    "agent-1b": "10.128.1.107",
    "agent-2a": "10.128.1.108",
    "agent-2b": "10.128.1.109",
    "agent-1c": "10.128.1.114",
    "manacor": None,
}
# The long-term probes. Their survival is an invariant of every run (the
# chaos-extrem brief makes it a stop condition), and until I17 below nothing
# checked it: `nested-1` disappeared at some point between 2026-09-10 and
# 2026-09-15 and every run in between said "all invariants held".
PROBES = ["cloud-probe", "ubuntu-probe"]

# etcd's NOSPACE quota is checked against the physical backend size. Past this
# share of it, the tier is on a clock -- and nothing in the product says so.
ETCD_WARN = 0.80

# What a run did NOT get to look at. An unreachable node used to be a silent
# `continue`, which turned every injected fault into a free pass for the
# node-side half of I1, I2 and I3. It is still not a violation -- that is what
# the fault is for -- but it is no longer invisible.
SKIPPED = []

# Nodes the caller deliberately broke for this check. Their NotReady is the
# experiment, not a finding.
EXPECT_DOWN = set()

NODE_OF_CLUSTER = {
    "cluster-1": ["agent-1a", "agent-1b", "agent-1c", "manacor"],
    "cluster-2": ["agent-2a", "agent-2b"],
}
CLOUD_PORT = int(os.environ.get("CHAOS_CLOUD_PORT", "3000"))
CLUSTER_PORT = int(os.environ.get("CHAOS_CLUSTER_PORT", "3001"))

SSH = [
    "ssh", "-i", os.path.expanduser("~/.ssh/id_ed25519"),
    "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
    "-o", "ConnectTimeout=6", "-o", "BatchMode=yes", "-o", "LogLevel=ERROR",
]

# Objects that were here before the chaos run and are none of its business.
# `ubuntu-probe` joined the list with the first Ubuntu boot from `--from-url`;
# the `fleet-*` VMs are the placement fleet on manacor. A prefix and not eleven
# names, because that set grows without this file hearing about it.
TABU_VMS = {"cloud-probe", "nested-1", "ubuntu-probe"}
TABU_VM_PREFIXES = ("fleet-",)
TABU_TENANTS = {"guide-demo"}


# --- plumbing ---------------------------------------------------------------

def get(ip, port, path, timeout=8):
    url = f"{mtls.scheme()}://{ip}:{port}{path}"
    try:
        with mtls.urlopen(urllib.request.Request(url), timeout=timeout) as r:
            return json.loads(r.read().decode())
    except Exception as e:  # unreachable is itself data, not a crash
        return {"__error__": f"{type(e).__name__}: {e}"}


def items(doc):
    if not isinstance(doc, dict) or "__error__" in doc:
        return []
    return doc.get("items") or []


def sh(node, cmd, timeout=25):
    """Run a shell command on a node. Returns (rc, stdout)."""
    host = NODE_HOST.get(node, "__missing__")
    if host == "__missing__":
        return 127, ""
    argv = ["bash", "-c", cmd] if host is None else SSH + [f"root@{host}", cmd]
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout
    except subprocess.TimeoutExpired:
        return 124, ""


def sh_ip(ip, cmd, timeout=25):
    """A shell on a controller by address. `sh()` resolves node NAMES through
    NODE_HOST, and the controller replicas are not in it."""
    try:
        p = subprocess.run(SSH + [f"root@{ip}", cmd],
                           capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout
    except subprocess.TimeoutExpired:
        return 124, ""


def first_alive(ips, port, path):
    for ip in ips:
        d = get(ip, port, path)
        if "__error__" not in d:
            return ip, d
    return None, {"__error__": "no replica answered"}


# --- state collection -------------------------------------------------------

class State:
    def __init__(self):
        self.cloud_ip, self.cloud_vms = first_alive(CLOUD, CLOUD_PORT, "/apis/meister.io/v1/vms")
        self.cloud_vms = items(self.cloud_vms)
        self.tenants = items(first_alive(CLOUD, CLOUD_PORT, "/apis/meister.io/v1/tenants")[1])
        self.fips = items(first_alive(CLOUD, CLOUD_PORT, "/apis/meister.io/v1/floatingips")[1])
        self.fpools = items(first_alive(CLOUD, CLOUD_PORT, "/apis/meister.io/v1/floatingpools")[1])
        self.images = items(first_alive(CLOUD, CLOUD_PORT, "/apis/meister.io/v1/images")[1])
        self.clusters = items(first_alive(CLOUD, CLOUD_PORT, "/apis/meister.io/v1/clusters")[1])
        # The rest of what carries a phase at the cloud. I19 judges every
        # object of both tiers, and an invariant that reads only the kinds
        # some older check happened to need is the D-H1 shape again.
        self.cloud_phased = {"vms": self.cloud_vms, "images": self.images}
        for kind in ("volumes", "volumesnapshots", "storagepools", "routers"):
            self.cloud_phased[kind] = items(
                first_alive(CLOUD, CLOUD_PORT, f"/apis/meister.io/v1/{kind}")[1])

        self.cl_vms = {}      # cluster -> [vm]
        self.cl_nodes = {}    # cluster -> [node]
        self.cl_vols = {}     # cluster -> [volume]
        self.cl_pools = {}
        self.cl_events = {}
        self.cl_phased = {}   # cluster -> kind -> [object], for I19
        self.cl_ip = {}
        for name, ips in CLUSTERS.items():
            ip, d = first_alive(ips, CLUSTER_PORT, "/apis/meister.io/v1/vms")
            self.cl_ip[name] = ip
            self.cl_vms[name] = items(d)
            self.cl_nodes[name] = items(get(ip, CLUSTER_PORT, "/apis/meister.io/v1/nodes")) if ip else []
            self.cl_vols[name] = items(get(ip, CLUSTER_PORT, "/apis/meister.io/v1/volumes")) if ip else []
            self.cl_pools[name] = items(get(ip, CLUSTER_PORT, "/apis/meister.io/v1/storagepools")) if ip else []
            self.cl_events[name] = items(get(ip, CLUSTER_PORT, "/apis/meister.io/v1/events")) if ip else []
            self.cl_phased[name] = {"vms": self.cl_vms[name], "volumes": self.cl_vols[name],
                                    "storagepools": self.cl_pools[name]}
            for kind in ("volumesnapshots", "routers", "images"):
                self.cl_phased[name][kind] = items(
                    get(ip, CLUSTER_PORT, f"/apis/meister.io/v1/{kind}")) if ip else []

        # one shell round-trip per node, everything the node-side checks need
        self.node_probe = {}
        for node in NODE_HOST:
            self.node_probe[node] = self.probe(node)

    def probe(self, node):
        cmd = r"""
echo "###CH"
# A VMM is a process whose COMMAND is cloud-hypervisor, and the awk on
# `$2` is what says so. `grep cloud-hypervisor` over the whole command
# line matched anything that merely mentioned it -- and on manacor, where
# `sh()` runs the probe locally instead of over ssh, that includes the
# shell running this very check. Round 4's e2e got
# `I3 orphan vmm on manacor for dead vm f60492d8-...` out of it, which is
# the id of the session that was doing the asking: I3 pulls the first uuid
# out of the line, and the line was a scratch path. A harness that reports
# its own toolchain as a leak is worse than one that reports nothing.
ps -eo pid,args --no-headers 2>/dev/null | awk '$2 ~ /(^|\/)cloud-hypervisor$/' | sed 's/  */ /g'
echo "###TAP"
ip -o link 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1
echo "###VNI"
ip -d link show type vxlan 2>/dev/null | grep -oE 'vxlan id [0-9]+' | awk '{print $3}'
echo "###LV"
lvs --noheadings -o lv_name,vg_name,lv_size 2>/dev/null | sed 's/^ *//'
echo "###FILES"
ls /var/lib/meisterstack/volumes 2>/dev/null
echo "###REDB"
stat -c %s /var/lib/meisterstack/agent.redb 2>/dev/null || echo 0
echo "###PID"
systemctl show -p MainPID --value meister-agent 2>/dev/null || echo 0
echo "###ACTIVE"
systemctl is-active meister-agent 2>/dev/null
echo "###NFT"
nft -j list ruleset 2>/dev/null | head -c 400000
echo "###ADDR"
ip -o -4 addr show 2>/dev/null | awk '{print $2" "$4}'
echo "###DF"
df -k --output=pcent,target / 2>/dev/null | tail -1
echo "###END"
"""
        rc, out = sh(node, cmd)
        d = {"rc": rc, "raw": out}
        cur = None
        buf = defaultdict(list)
        for line in out.splitlines():
            if line.startswith("###"):
                cur = line[3:]
                continue
            if cur and line.strip():
                buf[cur].append(line.rstrip())
        d.update({k: v for k, v in buf.items()})
        pid = (buf.get("PID") or ["0"])[0]
        d["agent_pid"] = int(pid) if pid.isdigit() else 0
        d["active"] = (buf.get("ACTIVE") or [""])[0]
        redb = (buf.get("REDB") or ["0"])[0]
        d["redb"] = int(redb) if redb.isdigit() else 0
        return d

    def agent_rss_fd(self, node):
        pid = self.node_probe[node].get("agent_pid", 0)
        if not pid:
            return None, None
        rc, out = sh(node, f"grep VmRSS /proc/{pid}/status 2>/dev/null; ls /proc/{pid}/fd 2>/dev/null | wc -l")
        rss = fd = None
        for line in out.splitlines():
            m = re.match(r"VmRSS:\s+(\d+)", line)
            if m:
                rss = int(m.group(1))
            elif line.strip().isdigit():
                fd = int(line.strip())
        return rss, fd


# --- the invariants ---------------------------------------------------------

def uid(o):
    return o.get("metadata", {}).get("uid")


def name(o):
    return o.get("metadata", {}).get("name")


def spec(o):
    return o.get("spec") or {}


def status(o):
    return o.get("status") or {}


def ours(o):
    n = name(o)
    return n not in TABU_VMS and not n.startswith(TABU_VM_PREFIXES)


def check(st, base):
    """Returns list of (id, message). Empty list = everything held."""
    v = []
    all_cl_vms = [(c, x) for c in CLUSTERS for x in st.cl_vms[c]]

    # I1 — no VM bound to two nodes.
    # Two ways this can show: the same VM object naming two nodes across the
    # tiers' copies, or one VM's disk image alive on two nodes at once.
    seen_by_uid = defaultdict(set)
    for c, x in all_cl_vms:
        n = spec(x).get("nodeName")
        if n:
            seen_by_uid[uid(x)].add((c, n))
    for u, places in seen_by_uid.items():
        if len(places) > 1:
            v.append(("I1", f"vm uid {u} bound to {sorted(places)}"))
    # the node-side half: one VM id must not run on two nodes
    running_on = defaultdict(set)
    for node, p in st.node_probe.items():
        for line in p.get("CH", []):
            m = re.search(r"--api-socket\s+(\S+)", line) or re.search(r"/(?:run|var)/\S*?/([0-9a-f-]{36})", line)
            if m:
                running_on[os.path.basename(m.group(1)).replace(".sock", "")].add(node)
    for vmid, nodes in running_on.items():
        if len(nodes) > 1:
            v.append(("I1", f"vmm for {vmid} alive on {sorted(nodes)}"))

    # I2 — every Running VM has exactly one binding AND the node confirms it.
    # A VM with a deletionTimestamp is mid-teardown: its object outlives its
    # vmm by design, so "Running with no process" is the teardown, not a lie.
    for c, x in all_cl_vms:
        if status(x).get("phase") != "Running":
            continue
        if x.get("metadata", {}).get("deletionTimestamp"):
            continue
        n = spec(x).get("nodeName")
        if not n:
            v.append(("I2", f"{c}/{name(x)} Running with no nodeName"))
            continue
        if status(x).get("nodeName") not in (None, n):
            v.append(("I2", f"{c}/{name(x)} spec node {n} != status node {status(x).get('nodeName')}"))
        p = st.node_probe.get(n)
        if p is None or p["rc"] != 0:
            # Not a violation: an unreachable node is the fault, not the bug.
            # Recorded, so the verdict can say how much of it actually ran.
            SKIPPED.append(("I2", n, f"{c}/{name(x)}: node not reachable"))
            continue
        u = uid(x)
        if not any(u in line for line in p.get("CH", [])):
            v.append(("I2", f"{c}/{name(x)} Running on {n} but no vmm process there"))

    # I3 — a delete leaves nothing. Anything named after a VM the API no longer
    # knows, and that was not there at baseline, is residue.
    # A tier that did not answer teaches nothing about what is alive: with an
    # empty listing every running vmm looks like an orphan, which is how a
    # controller outage turns into a page of false I3 lines.
    api_blind = any(st.cl_ip.get(c) is None for c in CLUSTERS) or st.cloud_ip is None
    live_uids = {uid(x) for _, x in all_cl_vms} | {uid(x) for x in st.cloud_vms}
    live_names = {name(x) for _, x in all_cl_vms} | {name(x) for x in st.cloud_vms}
    for node, p in st.node_probe.items():
        if p["rc"] != 0 or api_blind:
            continue
        for line in p.get("CH", []):
            m = re.search(r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", line)
            if m and m.group(1) not in live_uids:
                v.append(("I3", f"orphan vmm on {node} for dead vm {m.group(1)}"))
        for tap in p.get("TAP", []):
            if not tap.startswith(("tap", "meister-vx")):
                continue
            if tap in base.get("taps", {}).get(node, []):
                continue
            owner = tap.replace("tap", "").replace("meister-vx", "")
            if tap.startswith("tap") and not any(owner in str(u) for u in live_uids):
                v.append(("I3", f"orphan tap {tap} on {node}"))
        for f in p.get("FILES", []):
            if f in base.get("files", {}).get(node, []):
                continue
            stem = f.split(".")[0]
            if stem.startswith("chaos-") and stem not in live_names:
                v.append(("I3", f"orphan volume file {f} on {node}"))
        for lv in p.get("LV", []):
            fields = lv.split()
            if not fields:
                continue
            if lv in base.get("lvs", {}).get(node, []):
                continue
            if fields[0].startswith("chaos-") and not any(fields[0].endswith(str(u)[-12:]) for u in live_uids):
                v.append(("I3", f"orphan LV {fields[0]} on {node}"))

    # I4 — tenant B never reaches tenant A. Any nftables counter that a drop
    # rule owns and that moved off zero is a crossing that happened.
    for node, p in st.node_probe.items():
        blob = "\n".join(p.get("NFT", []))
        if not blob.strip():
            continue
        try:
            rs = json.loads(blob)
        except Exception:
            continue
        for ent in rs.get("nftables", []):
            rule = ent.get("rule")
            if not rule:
                continue
            verdict = json.dumps(rule.get("expr", []))
            if '"drop"' not in verdict:
                continue
            for e in rule.get("expr", []):
                c = e.get("counter")
                if isinstance(c, dict) and c.get("packets", 0) > 0:
                    v.append(("I4", f"{node}: drop rule in {rule.get('chain')} counted "
                                    f"{c['packets']} pkts — a tenant crossing was attempted/passed"))

    # I5 — memory is never oversubscribed on a node.
    for c in CLUSTERS:
        cap = {name(n): (status(n).get("capacity") or {}) for n in st.cl_nodes[c]}
        booked = defaultdict(lambda: [0, 0])
        for x in st.cl_vms[c]:
            n = spec(x).get("nodeName")
            if not n:
                continue
            inner = spec(x).get("vm") or {}
            booked[n][0] += int(inner.get("memory_mib") or 0)
            booked[n][1] += int(inner.get("vcpus") or 0)
        for n, (mem, cpu) in booked.items():
            if n not in cap:
                continue
            have = int(cap[n].get("memMib") or 0)
            if have and mem > have:
                v.append(("I5", f"{c}/{n}: {mem} MiB bound over {have} MiB capacity"))

    # I6 — a hard anti-affinity term is never violated.
    for c in CLUSTERS:
        by_node = defaultdict(list)
        for x in st.cl_vms[c]:
            n = spec(x).get("nodeName")
            if n:
                by_node[n].append(x)
        for n, vms in by_node.items():
            for x in vms:
                for term in spec(x).get("antiAffinity") or []:
                    if not term.get("required", True):
                        continue
                    sel = term.get("selector") or {}
                    for other in vms:
                        if uid(other) == uid(x):
                            continue
                        lbl = other.get("metadata", {}).get("labels") or {}
                        if all(lbl.get(k) == w for k, w in sel.items()):
                            v.append(("I6", f"{c}/{n}: {name(x)} and {name(other)} "
                                            f"share a required anti-affinity term {sel}"))

    # I7 — a placed VM sits on a node that carries its selector's labels.
    for c in CLUSTERS:
        lbls = {name(n): (spec(n).get("labels") or {}) for n in st.cl_nodes[c]}
        for x in st.cl_vms[c]:
            n = spec(x).get("nodeName")
            sel = spec(x).get("nodeSelector") or {}
            if not n or not sel:
                continue
            have = lbls.get(n, {})
            missing = {k: w for k, w in sel.items() if have.get(k) != w}
            if missing:
                v.append(("I7", f"{c}/{name(x)} on {n} which lacks {missing}"))
    # the same one tier up
    cl_lbls = {name(c): (spec(c).get("labels") or {}) for c in st.clusters}
    for x in st.cloud_vms:
        c = spec(x).get("clusterName")
        sel = spec(x).get("clusterSelector") or {}
        if not c or not sel:
            continue
        missing = {k: w for k, w in sel.items() if cl_lbls.get(c, {}).get(k) != w}
        if missing:
            v.append(("I7", f"cloud/{name(x)} on cluster {c} which lacks {missing}"))

    # I8 — a tenant quota is never exceeded.
    use = defaultdict(lambda: [0, 0, 0])
    for x in st.cloud_vms:
        t = spec(x).get("tenant")
        if not t:
            continue
        inner = spec(x).get("vm") or {}
        use[t][0] += 1
        use[t][1] += int(inner.get("vcpus") or 0)
        use[t][2] += int(inner.get("memory_mib") or 0)
    for t in st.tenants:
        q = spec(t).get("quota") or {}
        n = name(t)
        vms, vcpus, mem = use[n]
        for got, lim, what in ((vms, q.get("maxVms"), "vms"),
                               (vcpus, q.get("maxVcpus"), "vcpus"),
                               (mem, q.get("maxMemMib"), "memMib")):
            if lim is not None and got > lim:
                v.append(("I8", f"tenant {n}: {what} {got} over quota {lim}"))
        rep = (status(t).get("used") or {})
        if rep and (rep.get("vms"), rep.get("vcpus"), rep.get("memMib")) != (vms, vcpus, mem):
            v.append(("I8", f"tenant {n}: reported usage {rep} != counted "
                            f"{{'vms': {vms}, 'vcpus': {vcpus}, 'memMib': {mem}}}"))

    # I9 — a volume an attached VM holds never disappears.
    for c in CLUSTERS:
        vols = {name(x) for x in st.cl_vols[c]}
        for x in st.cl_vms[c]:
            for vol in (spec(x).get("vm") or {}).get("volumes") or []:
                # `volume` is the field this API has (agent_api::spec::NewVolume);
                # the three below it are shapes that were guessed at when this
                # was written and that the server has never accepted. Kept
                # beside it rather than instead of it, because an invariant
                # that reads nothing reports nothing -- which is how I9 passed
                # on every run while S6 could not create the vm at all.
                claim = (vol.get("volume") or vol.get("volume_name")
                         or vol.get("volumeName") or vol.get("claim"))
                if claim and claim not in vols:
                    v.append(("I9", f"{c}/{name(x)} holds volume {claim} which no longer exists"))

    # I10 handled by the scenario runner (needs a before/after of one delete).

    # I11 — metric series do not grow with the object count. Nothing serves
    # /metrics in this fleet, which is itself the finding, raised once.
    # (see chaos.py: metrics_probe)

    # I12 — no event per reconcile pass. Counted by the caller across a window.

    # I13 — nothing grows without bound: recorded here, judged by the caller.

    # I14 — a floating IP is never handed out twice.
    holders = defaultdict(list)
    for f in st.fips:
        a = spec(f).get("address")
        if a:
            holders[a].append(name(f))
    for a, hs in holders.items():
        if len(hs) > 1:
            v.append(("I14", f"floating ip {a} claimed by {hs}"))
    # and never assigned to two VMs
    vm_of = defaultdict(list)
    for f in st.fips:
        t = spec(f).get("vmName") or spec(f).get("vm")
        if t:
            vm_of[(spec(f).get("address"), t)].append(name(f))

    # extra, cheap and load-bearing: the tiers must agree on where a VM is.
    cloud_by_uid = {uid(x): x for x in st.cloud_vms}
    for c, x in all_cl_vms:
        cu = (x.get("metadata", {}).get("labels") or {}).get("meister.io/cloud-uid")
        if cu and cu in cloud_by_uid:
            up = spec(cloud_by_uid[cu]).get("clusterName")
            if up and up != c:
                v.append(("I1", f"cloud says {name(x)} is on {up}, but {c} holds a copy"))

    # I15 — etcd stays well under its quota. Rollout Neutron lost two hours to
    # a full store that looked like a product bug from above, and this run found
    # cluster-1 at 99 % before it started. One member per tier: the members of a
    # raft group grow together, and three ssh round-trips is what this can cost.
    for tier, ip in (("cloud", CLOUD[0]), ("cluster-1", CLUSTERS["cluster-1"][0]),
                     ("cluster-2", CLUSTERS["cluster-2"][0])):
        if not ip:
            SKIPPED.append(("I15", tier, "no replica answered"))
            continue
        rc, out = sh_ip(ip, "etcdctl endpoint status -w json 2>/dev/null")
        m = re.search(r'"dbSize":(\d+)', out or "")
        q = re.search(r'"dbSizeQuota":(\d+)', out or "")
        if not (m and q and int(q.group(1))):
            SKIPPED.append(("I15", tier, "etcdctl gave no status"))
            continue
        share = int(m.group(1)) / int(q.group(1))
        if share > ETCD_WARN:
            v.append(("I15", f"{tier}: etcd backend at {share*100:.0f}% of quota "
                             f"({int(m.group(1))//1048576} MiB); writes stop at 100%"))

    # I16 — a cluster still has the nodes it is supposed to have. A node that
    # vanishes from the roster is a violation; a node that is merely NotReady is
    # an observation, because that is what half this harness exists to cause.
    for cname, want in NODE_OF_CLUSTER.items():
        have = {name(n): (status(n) or {}).get("ready") for n in st.cl_nodes.get(cname, [])}
        for n in want:
            if n not in have:
                v.append(("I16", f"{cname}: node {n} is not in the roster at all"))
            elif have[n] is not True and n not in EXPECT_DOWN:
                SKIPPED.append(("I16", n, f"{cname}: NotReady"))

    # I17 — the long-term probes are still there. Compared against the baseline,
    # so this asks "did THIS run lose one", not "is the lab as it was in August".
    known = set(base.get("probes") or [])
    if known:
        alive = {name(x) for x in st.cloud_vms}
        for pr in sorted(known):
            if pr not in alive:
                v.append(("I17", f"long-term probe {pr} is gone (it was there at baseline)"))

    # I18 — the contradiction that `Unknown` can hide. A guest in Unknown on a
    # node the cluster calls Ready is not a fault in flight: the node IS
    # reporting, so it should be reporting this guest too.
    for cname, xs in st.cl_nodes.items():
        ready = {name(n) for n in xs if (status(n) or {}).get("ready") is True}
        for c, x in all_cl_vms:
            if c != cname or status(x).get("phase") != "Unknown":
                continue
            n = spec(x).get("nodeName") or status(x).get("nodeName")
            if n in ready:
                v.append(("I18", f"{c}/{name(x)} is Unknown while its node {n} is Ready"))

    # I19 — every object explains itself. Struktur 4 made a phase a derived
    # value with `reason`, `message` and `since`, and `deploy/chaos/phases.py`
    # was written to check that after the roll-out. Silas asked for it to be
    # part of the verdict rather than a thing somebody remembers to run, so
    # the rule is imported from there and applied to every phased object of
    # both tiers. A hole is a violation: an object standing in a non-terminal
    # phase with nothing to say is the state the whole round removed.
    for kind, xs in st.cloud_phased.items():
        for x in xs:
            flag = phase_hole(x)
            if flag:
                pst = status(x)
                v.append(("I19", f"cloud/{kind}/{name(x)}: {flag} "
                                 f"(phase={pst.get('phase')!r} reason={pst.get('reason')!r} "
                                 f"since={pst.get('since')!r})"))
    for cname, kinds in st.cl_phased.items():
        for kind, xs in kinds.items():
            for x in xs:
                flag = phase_hole(x)
                if flag:
                    pst = status(x)
                    v.append(("I19", f"{cname}/{kind}/{name(x)}: {flag} "
                                     f"(phase={pst.get('phase')!r} reason={pst.get('reason')!r} "
                                     f"since={pst.get('since')!r})"))

    return v


def snapshot_baseline(st):
    b = {"taps": {}, "files": {}, "lvs": {}, "redb": {}, "vnis": {},
         "probes": [name(x) for x in st.cloud_vms if name(x) in PROBES]}
    for node, p in st.node_probe.items():
        b["taps"][node] = p.get("TAP", [])
        b["files"][node] = p.get("FILES", [])
        b["lvs"][node] = p.get("LV", [])
        b["vnis"][node] = p.get("VNI", [])
        b["redb"][node] = p.get("redb", 0)
    return b


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--baseline", action="store_true")
    ap.add_argument("--seed", default="-")
    ap.add_argument("--tag", default="")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--expect-down", default="",
                    help="comma-separated nodes this caller broke on purpose")
    a = ap.parse_args()
    EXPECT_DOWN.update(n for n in a.expect_down.split(",") if n)

    bpath = os.path.join(OUT, "baseline.json")
    st = State()

    if a.baseline:
        json.dump(snapshot_baseline(st), open(bpath, "w"), indent=1)
        print(f"baseline written: {bpath}")
        return 0

    base = json.load(open(bpath)) if os.path.exists(bpath) else {}
    viol = check(st, base)

    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    with open(os.path.join(OUT, "findings.txt"), "a") as fh:
        for i, msg in viol:
            fh.write(f"{stamp}\t{i}\t{a.tag}\tseed={a.seed}\t{msg}\n")

    # The verdict says what it looked at. "all invariants held" on its own is
    # the sentence this checker used to print at a lab with a node four days
    # gone, two guests in Unknown and a vanished probe.
    cover = ""
    if SKIPPED:
        by = defaultdict(list)
        for inv, who, why in SKIPPED:
            by[inv].append(who)
        cover = "; ".join(f"{i}: not checked on {', '.join(sorted(set(w)))}"
                          for i, w in sorted(by.items()))
        with open(os.path.join(OUT, "coverage.txt"), "a") as fh:
            fh.write(f"{stamp}\t{a.tag}\tseed={a.seed}\t{cover}\n")

    if not a.quiet:
        if viol:
            for i, msg in viol:
                print(f"FAIL {i}  {msg}")
        else:
            print("all invariants held" + (f" — but {cover}" if cover else
                                           " (everything was reachable)"))
    return 1 if viol else 0


if __name__ == "__main__":
    sys.exit(main())

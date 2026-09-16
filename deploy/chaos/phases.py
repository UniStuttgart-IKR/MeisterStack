#!/usr/bin/env python3
"""Every object with a phase, on both tiers, and whether it explains itself.

The check struktur 4 is about: after the first pass of the new controllers no
object may stand in a non-terminal phase without `reason` and `since`, and
none may say `Unrecorded`. Prints one line per object and a summary; exit 1
if the summary has a hole in it. Blackbox over the REST tiers, like the rest
of this directory.
"""
import json
import sys

import ops
from invariants import CLUSTERS

KINDS_CLOUD = ["vms", "volumes", "volumesnapshots", "images", "storagepools", "routers"]
KINDS_CLUSTER = ["vms", "volumes", "volumesnapshots", "storagepools", "routers", "images"]
RESTING = {"Ready", "Running", "Stopped", "Paused", "Active", "Migrated", "Done", "Succeeded"}


def rows():
    for kind in KINDS_CLOUD:
        code, o = ops.cloud("GET", f"/{kind}")
        if code == 200:
            for i in o.get("items", []):
                yield "cloud", kind, i
    for cname in CLUSTERS:
        for kind in KINDS_CLUSTER:
            code, o = ops.cluster(cname, "GET", f"/{kind}")
            if code == 200:
                for i in o.get("items", []):
                    yield cname, kind, i


def main():
    holes = []
    n = 0
    for tier, kind, obj in rows():
        st = obj.get("status") or {}
        name = obj["metadata"]["name"]
        phase, reason, since, msg = st.get("phase"), st.get("reason"), st.get("since"), st.get("message")
        n += 1
        flag = ""
        if phase is None:
            flag = "NO-PHASE"
        elif reason == "Unrecorded":
            flag = "UNRECORDED"
        elif phase not in RESTING and not reason:
            flag = "NO-REASON"
        elif not since:
            flag = "NO-SINCE"
        if flag:
            holes.append((tier, kind, name, flag))
        print(f"{tier:10} {kind:16} {name:26} {phase or '-':12} {reason or '':18} {since or '':27} {(msg or '')[:70]}{'  <-- ' + flag if flag else ''}")
    print(f"\n{n} objects, {len(holes)} holes")
    for h in holes:
        print("  ", *h)
    json.dump({"objects": n, "holes": holes}, open("out/phases.json", "w"))
    return 1 if holes else 0


if __name__ == "__main__":
    sys.exit(main())

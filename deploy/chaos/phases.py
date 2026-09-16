#!/usr/bin/env python3
"""Every object with a phase, on both tiers, and whether it explains itself.

The check struktur 4 is about: after the first pass of the new controllers no
object may stand in a non-terminal phase without `reason` and `since`, and
none may say `Unrecorded`. Prints one line per object and a summary; exit 1
if the summary has a hole in it. Blackbox over the REST tiers, like the rest
of this directory.

The judgement is a pure function of one object (`hole`), and nothing above it
imports `ops` or `invariants`. That is on purpose: `invariants.py` asks this
module for the rule (I19) and `ops.py` imports `invariants`, so a module-level
`import ops` here would close a cycle and break both. The transports are
imported inside `rows()`, where they are needed.
"""
import json
import sys

KINDS_CLOUD = ["vms", "volumes", "volumesnapshots", "images", "storagepools", "routers"]
# Struktur 4 gave SEVEN resources a phase with a reason, and this list held
# six: `vmmigrations` was the one nobody looked at, and the lab had sixteen
# records in it. A checker that does not name a kind cannot find anything in
# it -- D-H1, one more time.
KINDS_CLUSTER = ["vms", "volumes", "volumesnapshots", "storagepools", "routers",
                 "images", "vmmigrations"]
RESTING = {"Ready", "Running", "Stopped", "Paused", "Active", "Migrated", "Done", "Succeeded"}
# `Failed` is at rest for exactly one kind. A VmMigration has five phases and
# "the two ends are terminal: nothing retries a `Failed` migration by itself,
# because the thing that failed was an operation somebody asked for and asking
# again is somebody's decision"
# (shared/controller-api/src/resources/migration.rs:87-92). For a Vm or an
# Image, `Failed` is a stop the reconciler can leave again -- an image goes
# back to Ready the moment a node has the bytes -- so there it owes a reason
# like every other phase in flight.
RESTING_BY_KIND = {"vmmigrations": RESTING | {"Failed"}}


def hole(obj, kind=""):
    """The flag this object earns, or "" if it explains itself.

    One rule, one place: the CLI below and I19 in `invariants.py` cannot drift
    apart, which is the whole lesson of D-H4.
    """
    st = obj.get("status") or {}
    phase, reason, since = st.get("phase"), st.get("reason"), st.get("since")
    message = st.get("message")
    if phase is None:
        return "NO-PHASE"
    if reason == "Unrecorded":
        return "UNRECORDED"
    if phase not in RESTING_BY_KIND.get(kind, RESTING) and not reason:
        return "NO-REASON"
    # A terminal failure still has to say what stopped it -- that is what the
    # phase is FOR, and `Failed` resting is not `Failed` silent.
    if phase == "Failed" and not (reason or message):
        return "NO-WHY"
    if not since:
        return "NO-SINCE"
    return ""


def rows():
    import ops
    from invariants import CLUSTERS

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
        flag = hole(obj, kind)
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

# deploy/chaos

A fault injector and an invariant checker for the lab. Blackbox: it talks to
the two REST tiers and to a shell on the nodes, and imports no product code.

    ./selftest.sh                  does this harness still reach a tier at all?
    ./snapshot.sh                  freeze the running binaries as *.pre-chaos
    ./rollback.sh back | forward   the way back, and the way forward again
    ./invariants.py --baseline     record today's leftovers first
    ./invariants.py                check I1-I15 once
    ./scenarios.py --list          the fault catalogue
    ./scenarios.py I6              one scenario
    ./chaos.py --seed 4711 --steps 150
    ./chaos.py --cleanup           remove every chaos-* object on both tiers

Everything it creates is called `chaos-*`. Findings land one per line in
`out/findings.txt` (timestamp, invariant, tag, seed, sentence); the seeded
loop also writes its exact operation sequence to `out/seq-<seed>.log`.

`--baseline` matters: without it every leftover from an earlier run reads as a
leak of this one.

## selftest.sh, and why it is first in that list

The harness was written against a lab whose REST ports were plain http. Image
58 turned mTLS on, and from that moment every request it made died at the
first byte with `ApiError HTTP 0: BadStatusLine:  2` — TLS answering an http
client. Nothing in the harness said so; the first hour of the mini-chaos run
went into reading an exception. A tool whose whole job is to notice things has
to be able to notice that it is talking to a wall, and it has to be able to
notice it without twelve hosts.

`./selftest.sh` builds a throwaway CA with `tools/meister-ca`, starts an etcd
and both controller tiers on loopback with mTLS exactly as the fleet runs it,
proves the port really is TLS by meeting the wall on purpose, and then runs
`mini.py M0` against them. No root, no lab, no network; everything lives under
`/tmp/ms-chaos-controller` and is removed at the end (`KEEP=1` leaves it up).

`M0` is a scenario like any other and runs against the lab too: it asks every
endpoint — each replica separately, because D2 was invisible until they were
asked one at a time — for its discovery document, and judges the answer. A
transport failure there is reported AS a transport failure, which is the
confusion it exists to end.

The topology comes from the environment when it is given:
`CHAOS_CLOUD`, `CHAOS_CLUSTER1`, `CHAOS_CLUSTER2` (comma-separated; set and
empty means "there is no such tier here"), `CHAOS_CLOUD_PORT`,
`CHAOS_CLUSTER_PORT`. Unset is the lab's.

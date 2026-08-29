# deploy/chaos

A fault injector and an invariant checker for the lab. Blackbox: it talks to
the two REST tiers and to a shell on the nodes, and imports no product code.

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

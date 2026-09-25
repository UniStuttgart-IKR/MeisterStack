# Motivation and tradeoffs

MeisterStack explores VM orchestration for small labs and research clusters that
need local hardware access, tenant resources and several clusters under one API.
The thesis can use it to examine how desired-state control interacts with devices,
shared storage and processes that survive their controller.

| Goal | Design choice | Cost or limit |
| --- | --- | --- |
| Small runtime footprint | Rust services and selectable compiled drivers | Actual memory and CPU cost require measurement |
| Hardware extensibility | Trait-based device acquisition and capability reporting | Recovery behavior must be implemented for each driver |
| Cluster autonomy | Separate placement and local reconciliation | State must converge across two controller tiers |
| Inspectable failures | Persisted resources, conditions, events and local observations | Reports can be stale; diagnostics are not ownership proof |
| Repeatable hosts | Nix packages, modules and declarative inventory | Installation and external providers have separate failure modes |
| Conservative migration | Durable attempt identities and retained unknown outcomes | Unresolved attempts can block progress; receive-side gaps remain |

The project does not aim to replace every function of a general cloud platform.
Its present value is an inspectable implementation and an experiment platform.
Feature presence, functional correctness, fault tolerance and operating cost are
separate evaluation questions.

For thesis prose, distinguish the design rationale in this guide, source-backed
mechanisms in the other guides, and measured results recorded with configurations,
versions and failure conditions. Do not infer experimental results from comments
or passing unit tests.

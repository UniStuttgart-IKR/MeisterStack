# config/json — VM spec fixtures

These are **not** component configs. Each file is the body of a
`POST /vms` — a `NewVmSpec` — and what `meister … vm create -f <file>` sends.

They are fixtures first and samples second. Every `.json` in this directory
is parsed and validated by `components/agent/src/types.rs`
(`every_spec_in_the_repo_still_parses`), which is what keeps them honest:
`NewVmSpec` is `deny_unknown_fields`, so a field renamed in the code breaks
this directory in CI rather than in somebody's `curl`. That test is also the
promise every spec here was written under — a spec that meant something
before a field was added still means exactly that.

Keep the directory flat and keep every file a valid spec; the test walks it
without knowing any names.

| File | What it exercises |
|------|-------------------|
| `plain.json` | A VM with nothing special: default bridge, one cloned volume, no devices. |
| `example-vm.json` | The same, with the bridge named explicitly. |
| `gpu.json` | A mediated GPU through the `crosvm-gpu` driver, profile `venus`. |
| `nvrm.json` | A mediated NVIDIA vGPU through the `nvrm` driver, profile `4q`. |
| `passthrough.json` | A whole PCI device through the `vfio` driver. Note the spelling: the driver is `vfio`, while the agent config section that whitelists the address is `[[device.managed]]`. |

The device drivers named here have to be configured on the node the VM lands
on, or the spec is refused — by the agent at the edge, and by the scheduler
one tier up, which keeps such a VM away from a node that cannot serve it. See
`config/examples/agent.toml`.

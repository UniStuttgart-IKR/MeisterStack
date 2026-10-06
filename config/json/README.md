# VM specification fixtures

These JSON files contain agent `NewVmSpec` values for local
`meister agent vm create -f <file>` operations. They are not component TOML
configuration. Cloud VM creation wraps a VM specification with resource and
placement information; see [API](../../docs/API.md).

[Agent parser tests](../../components/agent/src/types.rs) enumerate the flat
directory and validate every JSON file. Keep files parseable and update paths,
boot arguments, and device selections before using them on another host.

| File | Purpose |
| --- | --- |
| `plain.json` | Filesystem volume and default bridge. |
| `example-vm.json` | Explicit bridge and image-specific boot arguments. |
| `gpu.json` | crosvm GPU backend with the `venus` profile. |
| `nvrm.json` | NVIDIA mediated backend with the `4q` profile. |
| `input.json` | virtio-input with an evdev node; the node must appear in `[device.input].evdev`, and the backend user needs read access. |
| `passthrough.json` | Exclusive PCI assignment through `vfio`; the address must appear in `device.managed`. |

Required files and driver profiles must exist on the target node. These fixtures
validate the specification format; they do not establish hardware availability
or prove that the embedded guest paths will boot on another installation.

# virtio-input driver

- Runs upstream rust-vmm `vhost-device-input`, one process per device.
- Configure `[device.input].binary` with the upstream executable path.
- Device spec: `{"driver":"input","partition":"mediated","profile":"evdev","params":{"evdev":"/dev/input/eventN"}}`.
- The backend user needs read access to that node. Admission rejects duplicate device numbers, including aliases.
- Backend arguments: `--socket-path PREFIX --event-list NODE`. The attachment uses `PREFIX0`, device type 18 and two 256-entry queues.
- No FIFO source or name override. Guest capabilities and name come from evdev.
- Use upstream revision `93f867e1b00061d425686e4faa5f2ca40125f18c` or a newer version containing the one-byte config-write fix; release 0.1.0 lacks it.
- Existing FIFO specs require migration. Stop existing input VMs before replacing the backend and agent.

Checks:

```sh
cargo test -p meister-input-driver
cargo clippy -p meister-input-driver --all-targets --no-deps -- -D warnings
cargo test -p meister-agent --lib a_node_with_the_input_section_claims_evdev
```

The ignored `upstream_guest_delivery` test takes `MEISTER_INPUT_BACKEND`,
`MEISTER_INPUT_DEVICE` and `MEISTER_INPUT_VERIFY`. The verifier executable
receives the socket path, boots a guest, checks events and stops the guest.
The test then checks backend and socket cleanup.

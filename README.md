# MeisterStack

MeisterStack is a lightweight Infrastructure-as-a-Service (IaaS) tool that enables the user to mange
virtual machines, block-storage and networking resources across multiple machines in multiple clusters.
Its goal is to enable small labs and research clusters with a cloud-like experience. It's architecture
is inspired by Kubernetes, Oakestra and OpenStack.

> [!WARNING]
> The project is at the moment considered in `ALPHA` stage, [most features are proven in the lab]("docs/FEATURES.md") but to reach
> `BETA`, long-term tests and support for Linstor and Vitastor is planned to support 1st-class NVMe-storage solutions.
> This project heavily used [AI for implementation and testing]("docs/AI_GUIDELINES.md"), when the project reaches `BETA` stage the generated
> code will be fully reviewed!

## Architecture

![Architecture](docs/diagrams/architecture.svg "Architecture of MeisterStack")

MeisterStacks has a two-tiered controll-plane with a cloud-level, that holds global data like tenants and manages authentication
and a cluster-level controll-plane that manages one cluster of hypervisors. Each hypervisor runs the MeisterStack agent that 
controlls the system. As hypervisor Cloud-Hypervisor is used, for NVIDIA GPU-sharing Project Leandro is used. Generic `virtio-gpus`
are managed by CrosVM. `vfio` is also supported.

## Quick Start

Requirements:


Prerequisites:

```bash
./get_patched_binaries.sh
cargo build
```

Setup local etcd (one for both tiers):

```bash
etcd --data-dir /tmp/ms-dev/etcd --listen-client-urls http://127.0.0.1:2379 --advertise-client-urls http://127.0.0.1:2379
```

Setup *cloud-tier*:

```bash
cp config/examples/cloud.toml /tmp/ms-dev/cloud.toml     # uses port 3000 and 50050
target/debug/meister-cloud-controller --config /tmp/ms-dev/cloud.toml
```

Setup *cluster-tier*:

```bash
cp config/examples/cluster.toml /tmp/ms-dev/cluster.toml    # uses port 3001 and 50051
target/debug/meister-cluster-controller --config /tmp/ms-dev/cluster.toml
```

Setup *agent*:

```bash
sudo target/debug/meister-agent --config config/agent.dev.toml
```
*Note that the image `nixos.raw` has to sit in `../images` relative to the config.


Create  *CLI-profiles*:

CLI-profiles are files that hold an endpoint and the required credentials. This makes it more easy to specify to which layer you want to talk.
For this example you can jsut use the `config/cli.dev.toml` or specify `--endpoint "http://127.0.0.1:3000" before each command.\

```bash
cp config/cli.dev.toml ~/.config/meisterstack/config.toml
```

Use MeisterStack:

```bash
meister api-resources
meister whoami

meister node ls --cluster cluster-1   # the agent must show up here before a VM can land
meister tenant create lab
meister image create nixos.raw --source /absolute/path/to/images/nixos.raw
meister vm create -t lab -f config/json/plain.json demo
meister vm ls -t lab
meister vm logs demo

meister --endpoint http://127.0.0.1:3001 vm ls   # to talk to the cluster-level API
```



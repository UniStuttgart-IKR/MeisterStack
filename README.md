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

MeisterStack is build for deployment with NixOS. Other distributions are not supported at the moment but it should be possible to
run the software stack on any Linux machine.


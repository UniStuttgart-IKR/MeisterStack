# Architecture

MeisterStack is a lightweight, modular virtual machine orchestrator designed for edge and lab clusters.
A two-tier control plane manages independent clusters of bare-metal nodes, each of which runs a node agent.
The system's modular architecture makes it extensible to support new hardware, such as specialized PCIe devices.

MeisterStack is written in Rust and is fully open source.

This document describes the target architecture of MeisterStack.

## Design Goals

The architecture's design is guided by four main goals. The first is **modularity**, which features an advanced trait system that abstracts infrastructure such as networking, devices, storage, and the hypervisor itself. This makes replacing the underlying technologies possible.

The second design goal is to be **lightweight**. While modern hardware, especially server hardware, is very powerful, designing lightweight software is no longer a top priority. However, hardware constraints are still real on edge and lab clusters. Therefore low RAM and CPU usage are key requirements for the system to be viable on less capable hardware.
To achieve this goal, MeisterStack allows the exclusion of unused backends via compile-time features.

**Maintainability** is another key design goal of the system. To make it suitable for lab and edge clusters, the maintenance overhead should be minimal. The most effective way to achieve this goal is to design the system to be as modular as possible with as few moving parts as possible. This also includes traceability of errors and the state of the system.

The fourth goal the orchestrator is designed for is **first-class PCIe device support**. This goal involves supporting specialized devices, such as GPUs and NICs, and abstracting them as resources that can be scheduled through the same driver model as compute, storage, and networking resources. In modern infrastructure, cooperative sharing of NICs and GPUs is often a key requirement for increasing compute density by sharing those devices between multiple VMs.

MeisterStack does not support loading drivers at runtime. The set of available drivers is fixed at compile time. It is also not a general replacement for OpenStack or Kubernetes as an all-in-one infrastructure-as-a-service platform.

## System Overview

![MeisterStack system overview](diagrams/architecture.svg)

*Figure 1: System overview. Showing the two-tier control plane, stretched over multiple clusters, controlling bare-metal nodes. Each node runs
exactly one agent. Each agent has its dedicated local `redb` instance, and each cluster has its dedicated `etcd` cluster, and the cloud
controller has its own `etcd` cluster. The arrows indicate the connection direction: Agent connects to its cluster, cluster connects to the cloud controller.*

MeisterStack is divided into three tiers (see Figure 1): the agent, which provisions resources on individual bare-metal nodes; the cluster controller, which handles the placement of virtual machines with respect to available resource constraints and shared resources; and the cloud controller, which acts as a gateway, handles tenants, and manages global resources. One cloud controller holds one or more cluster controllers, each of which manages a cluster of agents running on individual nodes.

The system uses a two-tier control plane to isolate public endpoints, particularly the REST API, from the part of the system that interacts directly with the infrastructure.
This reduces the attack surface on MeisterStack clusters by isolating public services from the rest of the system. The system's hierarchical design allows the cloud to be separated into multiple clusters comparable to OpenStack's regions or AWS availability zones. These clusters are isolated without interfering noise and can be distributed over multiple locations. 
Another positive side effect is that multiple small, independent etcd clusters, one per tier, scale better than one large etcd cluster stretched across all locations.
The downside of a two-tier control plane is that the system has more moving parts, making it harder to maintain and design a consistent data structure across the two layers with a clear separation of concerns.
Each cluster controller connects to the cloud controller via a gRPC stream, which also serves as a liveness test.

The agent communicated with the controll plane by gRPC stream. Despite the possibility to directly listen to the cluster's etcd, isolating the agent from the state store (cluster etcd) also reduces the attack surface of the system and enableing the controller to percisly control which information is visible to which agent and not sharing the complete cluster state 
with all agents. The agent connects to the cluster controller by gRPC stream (see Figure 1), which allows no open ports on the agent side and by monitoring the stream the
the controller can check the agents liveness.

As mentioned and shown in Figure 1, the system has three separate sources of truth, which makes data structure design more challenging. Cloud-etcd is tenant-oriented and stores tenant information, available images, available clusters, and VM stubs. A VM stub only describes the existence of a VM, its rough state, the owner (tenant), and the cluster in which the VM lives.
The cluster layer stores the placement of VMs, their full specifications, and their device inventories, as well as all registered agents of that cluster. The agent layer stores the concrete results of the VM, such as file paths, device names, and the process id.
There are multiple types of truth for storing information about virtual machines: the intent, which is stored in the cluster etcd and holds the desired state; the bookkeeping of what was done, which is stored in the agent's redb; and the reality that lives in the kernel. The bookkeeping is not a cache of the controller state it includes file paths, device names, and process IDs. That information only exists on the agent's redb and never leaves the agent's node
During reconciliation, the agent compares the kernel's actual state against the intent from the cluster controller and its own bookkeeping in redb, and resolves any discrepancies.

All infrastructure capabilities of the software stack are abstracted through Rust traits that are implemented in concrete drivers compiled into the agent. This behavior allows the system to replace the underlying software stack by implementing a driver that implements the respective trait for the specific software. For example, cloud-hypervisor could be replaced by qemu/libvirtd. As illustrated in Figure 1, the system provides traits for the hypervisor, devices, networking and storage. Other behaivoir like resource limitations are also abstracted by a trait but not illustrated in figure 1.
Storage and networking are also abstracted on the control plane by Rust traits to make the responsible backends interchangeable. To avoid confusion, these abstractions are called plugins instead of drivers. The driver selection happens in two steps: first, at compile time, the driver needs to be activated as a Cargo feature; second, at boot time, the agent's configuration file configures the driver so it can be instantiated. Because Rust has no stable ABI, and loading drivers dynamically would forfeit Rust's compile-time guarantees, the decision was made to include drivers at compile time. Driver specific parameters are passed through the agent and only interpreted by the driver itself. Adding a driver requires a rebuild of the agent.

## Components

### Agent

#### Drivers

#### CLI `agentctl`

### Cluster-Controller

### Cloud-Controller

## Miscellaneous

## Future Work


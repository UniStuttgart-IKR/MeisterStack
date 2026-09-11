# The hardened profile

The four files next to this one are the same four components as
`config/examples/`, configured for a deployment that is reachable from
somewhere other than a lab switch. They are meant to be copied and edited,
not diffed: every key is spelled out, including the ones that only say "this
is deliberately off".

The plain examples one directory up stay the reference for what each key
means. This directory only makes one decision, over and over: **which
network may reach which port, and what it has to prove to get in.**

## The exposure profile

```
        internet / users
               |
               |  TLS + client certificate, the ONE public edge
               v
   +---------------------------+
   |  cloud-controller         |  listen_api      0.0.0.0:3000   public
   |                           |  listen_session  <cloud-ip>:50050
   +---------------------------+
               ^
               |  mTLS, cluster network only
               |
   +---------------------------+
   |  cluster-controller       |  listen_api      127.0.0.1:3001  loopback
   |                           |  listen_session  <mgmt-ip>:50051 node net
   +---------------------------+
               ^
               |  mTLS, node network only
               |
   +---------------------------+
   |  agent                    |  no listening TCP socket at all
   +---------------------------+
```

Four rules, and the files below are only these four rules written in TOML:

1. **Only the cloud REST API is public**, and it terminates TLS and asks for
   a client certificate. Everything a user does arrives here.
2. **The cluster REST API is not public.** `listen_api` binds to `127.0.0.1`
   (reach it over an SSH tunnel) or to the management address of the box.
   It is an operator's and a debugger's door, not a user's — users go through
   the cloud.
3. **Both session ports are mTLS on an internal network.** They carry no user
   traffic; they carry a control plane talking to itself, and each side's
   certificate names it (`CN=system:node:<id>`, `CN=system:cluster:<name>`),
   which is what stops one node's key from asking about another node's VMs.
4. **The agent listens on nothing.** By design, and worth saying out loud
   because it is the part an operator would otherwise spend a firewall rule
   on: the agent's own API is a unix socket at `<run_dir>/agent.sock`, mode
   0600, and its link to the control plane is an *outbound* dial. There is no
   `listen_*` key in `agent.toml` because there is nothing to listen with.
   A node needs no inbound TCP permit for MeisterStack at all.

## The material

Everything below is a path to a PEM file, and every one of them comes out of
`tools/meister-ca`:

```sh
tools/meister-ca \
    --cloud   meister-cloud:cloud.example.net,10.128.1.103 \
    --cluster cluster-1:10.128.1.104 \
    --node    manacor \
    --admin   root
```

The SAN list is the addresses clients will actually dial. `localhost` and
`127.0.0.1` are always added, which is what makes rule 2's loopback binding
work with a real certificate rather than with a disabled check.

Relative paths in a config resolve against **that config file's own
directory**, so a config and its `pki/` directory can be copied as one unit.

## What this profile costs

Two prices, both deliberate, both worth knowing before the first outage:

- **No bearer token in the chain.** `auth.chain = ["mtls"]` means a caller
  with no certificate gets a 401 and no way to earn one over the API — the
  bootstrap the dev token exists for is closed. The first administrator
  certificate is therefore issued out of band, with `meister-ca --admin`, and
  copied to the operator by hand. That is one manual step, once, in exchange
  for no static credential existing anywhere.
- **`csr_auto_approve` stays off.** Certificate requests are recorded and a
  human runs `meister csr approve <name>`. With it on, the only thing
  between a caller and a certificate is the authenticator chain.

## The trap worth naming

A session endpoint only gets TLS if its URL says `https://`. The certificate
keys and the address are separate settings, and setting the first while
leaving the second spelled `http://` gives a plaintext session with no
warning anywhere — the credential is simply never used. Every session address
in these files is `https://` for that reason.

## The layout rule

Same as the plain examples, and worth repeating because it is easy to undo
with a well-meant edit: prose is `# `, a commented-out setting is `#key = …`
with no space, and **commented-out top-level keys stay above the first
`[table]` header**. Uncommenting a top-level key that sits below one would
silently move it into that table — the same class of bug as prepending a
section to a config that starts with top-level keys, which this project has
already caught once in the OpenNebula context rendering.

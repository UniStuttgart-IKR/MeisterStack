# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR
# scripts/meisterstack-install.sh, both shapes, into a scratch root.
#
# `--root` is what the script has for a machine it must not touch: every
# path goes below it, the paths inside the configs too, and no service and
# no group is made. So the whole of the script's decisions — which files,
# with what in them, and whether the agent accepts the config it wrote —
# can be checked in the sandbox against the real binaries.
{ nixpkgs, lib, pkgs, system, self }:
pkgs.runCommand "install-script"
{
  nativeBuildInputs = [ pkgs.bash pkgs.coreutils pkgs.gnused ];
} ''
  script=${../../scripts/meisterstack-install.sh}
  bin=${pkgs.meisterstack}/bin
  true=${pkgs.coreutils}/bin/true

  # --- single-node ----------------------------------------------------------
  root=$PWD/sn
  bash "$script" single-node --bin-dir "$bin" --hypervisor "$true" \
    --node-id rig --operator alice --bridge br-test --root "$root"
  test -x "$root/opt/meisterstack/bin/meister"
  test -x "$root/opt/meisterstack/bin/meister-agent"
  test -L "$root/usr/local/bin/meister"
  grep -q '^node_id = "rig"' "$root/etc/meisterstack/agent.toml"
  if grep -q '^controller_addr' "$root/etc/meisterstack/agent.toml"; then
    echo "a single node's agent names a controller"; exit 1
  fi
  grep -q 'socket_group = "meister"' "$root/etc/meisterstack/agent.toml"
  grep -q 'default_bridge = "br-test"' "$root/etc/meisterstack/agent.toml"
  grep -q "binary = \"$true\"" "$root/etc/meisterstack/agent.toml"
  grep -q 'default_profile = "local"' "$root/etc/meisterstack/cli.toml"
  grep -q "endpoint = \"unix://$root/run/meisterstack/agent/agent.sock\"" "$root/etc/meisterstack/cli.toml"
  grep -q "ExecStart=$root/opt/meisterstack/bin/meister-agent --config $root/etc/meisterstack/agent.toml" \
    "$root/etc/systemd/system/meister-agent.service"
  test -d "$root/var/lib/meisterstack/images"
  test -d "$root/var/lib/meisterstack/volumes"
  # The agent itself accepted the config: the script runs --check-config and
  # fails otherwise. Said twice on purpose, here as its own line.
  "$bin/meister-agent" --check-config --config "$root/etc/meisterstack/agent.toml"
  # A second run keeps every file.
  bash "$script" single-node --bin-dir "$bin" --hypervisor "$true" --node-id other --root "$root" \
    | grep -c "keeping" | grep -qx 3
  grep -q '^node_id = "rig"' "$root/etc/meisterstack/agent.toml"
  # …and --force replaces them.
  bash "$script" single-node --bin-dir "$bin" --hypervisor "$true" --node-id other --root "$root" --force >/dev/null
  grep -q '^node_id = "other"' "$root/etc/meisterstack/agent.toml"

  # --- cli, without an endpoint: on PATH and nothing written -----------------
  root=$PWD/cli0
  bash "$script" cli --bin-dir "$bin" --root "$root" | grep -q "no --endpoint"
  test -x "$root/opt/meisterstack/bin/meister"
  test ! -e "$root/opt/meisterstack/bin/meister-agent"
  test ! -e "$root/etc/meisterstack/cli.toml"

  # --- cli, with a control plane, its CA and an identity provider ------------
  root=$PWD/cli1
  echo "not a real certificate" > ca.crt
  bash "$script" cli --bin-dir "$bin" --root "$root" --profile lab \
    --endpoint https://cloud.example:3000 --ca-cert ca.crt \
    --oidc https://idp.example/oauth2/openid/meister-cli meister-cli >/dev/null
  grep -q 'default_profile = "lab"' "$root/etc/meisterstack/cli.toml"
  grep -q '^\[profiles.lab\]' "$root/etc/meisterstack/cli.toml"
  grep -q 'endpoint   = "https://cloud.example:3000"' "$root/etc/meisterstack/cli.toml"
  grep -q "ca_cert    = \"$root/etc/meisterstack/ca.crt\"" "$root/etc/meisterstack/cli.toml"
  grep -q 'type = "oidc", issuer = "https://idp.example/oauth2/openid/meister-cli", client_id = "meister-cli"' \
    "$root/etc/meisterstack/cli.toml"
  cmp ca.crt "$root/etc/meisterstack/ca.crt"
  # No credential the script could have invented: a certificate or a key is
  # a person's, never the machine's.
  if grep -q 'type = "mtls"\|token' "$root/etc/meisterstack/cli.toml"; then
    echo "the script wrote a credential"; exit 1
  fi

  # --- the refusals ------------------------------------------------------------
  ! bash "$script" cli --bin-dir "$bin" --root "$PWD/x1" --ca-cert ca.crt 2>/dev/null
  ! bash "$script" cli --bin-dir "$bin" --root "$PWD/x2" --endpoint http://cloud:3000 --ca-cert ca.crt 2>/dev/null
  ! bash "$script" single-node --bin-dir "$bin" --hypervisor "$true" --root "$PWD/x3" --endpoint http://x 2>/dev/null
  ! bash "$script" --bin-dir "$bin" 2>/dev/null
  touch $out
''

# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# Address helpers shared by the modules and a fleet inventory (meister-deploy's
# reads them as `lib.net`).
{ lib }:
rec {
  isIPv6 = address: lib.hasInfix ":" address;

  # An IPv6 address takes brackets in front of a port.
  hostPort = address: port:
    if isIPv6 address then "[${address}]:${toString port}"
    else "${address}:${toString port}";

  # Whether a listener bound to `::` also takes IPv4 connections. The Rust
  # listeners (std, mio and tokio alike) leave IPV6_V6ONLY as the kernel has
  # it: net.ipv6.bindv6only = 1 makes `::` IPv6-only, and with IPv6 left out of
  # the kernel it cannot be bound at all.
  dualStack = config:
    toString (config.boot.kernel.sysctl."net.ipv6.bindv6only" or 0) != "1"
    && !(builtins.elem "ipv6.disable=1" config.boot.kernelParams);

  # What a listener binds to take every address of the host: `0.0.0.0` is IPv4
  # only, `::` is both families where it is dual-stack.
  wildcard = config: if dualStack config then "::" else "0.0.0.0";

  # What a listener can be bound to ("address:port") and still answer at
  # `address:port`: that address itself, or a wildcard of its family.
  listensAnsweringAt = config: address: port:
    let
      wildcards =
        if isIPv6 address then [ "::" ]
        else [ "0.0.0.0" ] ++ lib.optional (dualStack config) "::";
    in
    map (a: hostPort a port) ([ address ] ++ wildcards);
}

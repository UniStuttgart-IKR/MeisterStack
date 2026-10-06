# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# Address helpers shared by the modules and the inventory.
{ lib }:
{
  # An IPv6 address takes brackets in front of a port.
  hostPort = address: port:
    if lib.hasInfix ":" address then "[${address}]:${toString port}"
    else "${address}:${toString port}";
}

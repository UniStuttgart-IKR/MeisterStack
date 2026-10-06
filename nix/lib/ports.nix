# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# The ports this stack listens on, in one place. nix/services.nix publishes the
# role table as `meisterstack.ports`, nix/addons.nix binds the addon listeners,
# and a deployment tool that derives addresses from an inventory reads the same
# numbers through `lib.ports` and `lib.addonPorts` instead of keeping a copy.
{
  roles = {
    cloud = { api = 3000; grpc = 50050; metrics = 9100; };
    cluster = { api = 3001; grpc = 50051; metrics = 9101; };
    agent = { metrics = 9102; migration = "49000-49099"; };
    etcd = { client = 2379; peer = 2380; };
  };

  # The addon listeners other hosts are pointed at: the Kanidm origin, Loki's
  # push endpoint and the OTLP receiver.
  addons = { kanidm = 8443; loki = 3100; otlp = 4317; };
}

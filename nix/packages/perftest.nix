# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# `ib_send_lat` and `ib_write_bw`: the two numbers an RDMA fabric is judged by.
#
# WHY THIS FILE EXISTS. `verify --suite rdma` makes three measurements between
# a declared pair of hosts — a round trip (`rping`, out of `rdma-core`), a
# latency (`ib_send_lat`) and a bandwidth (`ib_write_bw`) — and the last two
# come from linux-rdma/perftest, which the pinned nixpkgs does not have:
#
#     nix eval …#legacyPackages.x86_64-linux.perftest
#     error: attribute 'perftest' missing … Did you mean paratest?
#
# So it is built here. `rdma-core` IS in nixpkgs (60.0, measured) and carries
# `rping`, `ibv_devinfo` and the `librdmacm`/`libibverbs` this links against,
# which is why only this half needed a derivation.
#
# It is deliberately NOT in `nix/overlay.nix`: it is called straight from
# `nix/rdma.nix` with `pkgs.callPackage`, so a host that declares no RDMA nic
# neither evaluates nor builds it, and nothing outside that one module has to
# know it exists.
{ lib
, stdenv
, fetchFromGitHub
, autoconf
, automake
, libtool
, pkg-config
, rdma-core
, pciutils
}:

stdenv.mkDerivation rec {
  pname = "perftest";
  # A release tag and not a branch: a benchmark whose version moves is a
  # benchmark whose numbers cannot be compared with last month's.
  version = "26.04.17";

  src = fetchFromGitHub {
    owner = "linux-rdma";
    repo = "perftest";
    rev = version;
    hash = "sha256-oNvzQubmslZ4JUNww/wvWd54JDsDLamCDlorHWlNtaY=";
  };

  nativeBuildInputs = [ autoconf automake libtool pkg-config ];
  buildInputs = [ rdma-core pciutils ];

  # The tarball ships no `configure`; upstream's own build starts here.
  preConfigure = "./autogen.sh";

  meta = {
    description = "InfiniBand/RoCE latency and bandwidth benchmarks (ib_send_lat, ib_write_bw)";
    homepage = "https://github.com/linux-rdma/perftest";
    license = lib.licenses.gpl2Only;
    platforms = lib.platforms.linux;
  };
}
